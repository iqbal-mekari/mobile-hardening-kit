package com.mekari.securityagent

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Process
import java.io.File

/** Deterministic device collectors. Root-visible evidence is explicitly not ordinary-user proof. */
internal class SecurityChecks(context: Context, private val root: RootShell) {
    private val app = context.applicationContext
    private val redactor = Redactor

    fun run(checkId: String, config: SessionConfig, observation: Observation? = null): CheckResult = try {
        when (checkId) {
            "manifest" -> manifest(config)
            "storage" -> storage(config)
            "logs" -> logs(config)
            "network" -> network(config)
            "screenshots" -> screenshots(observation)
            "coverage" -> coverage()
            else -> CheckResult(checkId, "unavailable", "Unsupported check ID")
        }
    } catch (e: Exception) {
        CheckResult(checkId, "error", "Collector failed: ${safeMessage(e)}")
    }

    private fun manifest(config: SessionConfig): CheckResult {
        val pkg = packageInfo(config.targetPackage)
        val info = pkg.applicationInfo ?: throw IllegalStateException("Application metadata unavailable")
        val flags = info.flags
        val findings = mutableListOf<Finding>()
        val debug = flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
        val allowBackup = flags and ApplicationInfo.FLAG_ALLOW_BACKUP != 0
        val cleartext = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            flags and ApplicationInfo.FLAG_USES_CLEARTEXT_TRAFFIC != 0
        } else null
        if (debug) findings += finding("debuggable", "Application is debuggable", "medium", "Installed package metadata reports FLAG_DEBUGGABLE; configuration is not proof of exploitation.")
        if (allowBackup) findings += finding("backup", "Application allows backup", "low", "Installed package metadata reports FLAG_ALLOW_BACKUP; actual backup access depends on platform and attacker privileges.")
        if (cleartext == true) findings += finding("cleartext", "Application permits cleartext traffic", "medium", "Installed package metadata reports FLAG_USES_CLEARTEXT_TRAFFIC; no traffic interception was performed.")
        val permissions = pkg.requestedPermissions.orEmpty().take(MAX_ITEMS)
        val exported = exportedComponents(pkg).take(MAX_ITEMS)
        val data = buildString {
            append("package=${config.targetPackage}; versionCode=${versionCode(pkg)}; debuggable=$debug; allowBackup=$allowBackup; cleartextTraffic=$cleartext; ")
            append("requestedPermissions=${permissions.size}[${permissions.joinToString(limit = MAX_ITEMS)}]; exportedComponents=${exported.size}[")
            append(exported.joinToString(limit = MAX_ITEMS) { "${it.first}:${it.second}" })
            append("]")
        }
        return CheckResult("manifest", "complete", redactor.redact(data), findings)
    }

    private fun storage(config: SessionConfig): CheckResult {
        val info = app.packageManager.getApplicationInfo(config.targetPackage, 0)
        val userId = info.uid / ANDROID_PER_USER_RANGE
        if (userId != Process.myUid() / ANDROID_PER_USER_RANGE) return CheckResult("storage", "unavailable", "Target package belongs to another Android user; cross-user storage inspection is unsupported")
        val dirs = listOf("/data/user/$userId/${config.targetPackage}", "/data/user_de/$userId/${config.targetPackage}", "/storage/emulated/$userId/Android/data/${config.targetPackage}")
        val observed = mutableListOf<String>()
        for (path in dirs) {
            val command = "if [ -e ${RootShell.quote(path)} ]; then find ${RootShell.quote(path)} -maxdepth 2 -type f -print -quit; else echo __ABSENT__; fi"
            val result = root.run(command, 12_000)
            if (result.exitCode != 0) return CheckResult("storage", "unavailable", "Bounded root filesystem inspection failed (exit ${result.exitCode}); root-only observations do not demonstrate ordinary-attacker access")
            if (!result.stdout.contains("__ABSENT__")) {
                observed += if (result.stdout.lineSequence().any { it.startsWith(path) }) "${path.substringAfterLast('/')}: file presence observed (one bounded path; name withheld)" else "${path.substringAfterLast('/')}: directory presence observed"
            }
        }
        val details = "Root-only filesystem metadata for UID ${info.uid}: ${observed.joinToString("; ").ifEmpty { "no files observed in bounded locations" }}. File contents were not read; target data was not modified or deleted. Root-only visibility is not ordinary-attacker exploitation evidence."
        return CheckResult("storage", "complete", details)
    }

    private fun logs(config: SessionConfig): CheckResult {
        val info = app.packageManager.getApplicationInfo(config.targetPackage, 0)
        if (info.uid / ANDROID_PER_USER_RANGE != Process.myUid() / ANDROID_PER_USER_RANGE) return CheckResult("logs", "unavailable", "Target package belongs to another Android user; cross-user log inspection is unsupported")
        val pidResult = root.run("pidof ${RootShell.quote(config.targetPackage)}", 5_000)
        if (pidResult.exitCode != 0 || pidResult.stdout.trim().isEmpty()) return CheckResult("logs", "unavailable", "No target PID was available; target process log collection is unavailable")
        val pids = pidResult.stdout.trim().split(Regex("\\s+")).mapNotNull { it.toIntOrNull() }.filter { it > 0 }.distinct().take(8)
        if (pids.isEmpty()) return CheckResult("logs", "unavailable", "Target PID output was not valid")
        val lines = mutableListOf<String>()
        var successfulReads = 0
        for (pid in pids) {
            val owner = root.run("grep '^Uid:' /proc/$pid/status", 3_000)
            if (owner.exitCode != 0 || owner.stdout.trim().split(Regex("\\s+")).getOrNull(1)?.toIntOrNull() != info.uid) continue
            val result = root.run("logcat -d -t 500 --uid=${RootShell.quote(info.uid.toString())} --pid=${RootShell.quote(pid.toString())}", 8_000)
            if (result.exitCode != 0) continue
            successfulReads++
            result.stdout.lineSequence().take((100 - lines.size).coerceAtLeast(0)).forEach { lines += redactor.redact(it).take(500) }
            if (lines.size >= 100) break
        }
        if (successfulReads == 0) return CheckResult("logs", "unavailable", "UID-filtered logcat was unavailable or no matching target process was found; PID-only historical logs are never used")
        val status = if (successfulReads < pids.size || lines.size >= 100) "partial" else "complete"
        val limitation = if (status == "partial") " Some target process reads were unavailable or the output bound was reached." else ""
        return CheckResult("logs", status, "Collected ${lines.size} bounded logcat lines filtered by target UID ${info.uid} and PID; root-visible observations are not ordinary-attacker proof.$limitation\n" + lines.joinToString("\n").take(MAX_TEXT))
    }

    private fun network(config: SessionConfig): CheckResult {
        val info = app.packageManager.getApplicationInfo(config.targetPackage, 0)
        val uid = info.uid
        val v4 = root.run("cat /proc/net/tcp /proc/net/udp", 8_000)
        val v6 = root.run("cat /proc/net/tcp6 /proc/net/udp6", 8_000)
        if (v4.exitCode != 0 && v6.exitCode != 0) return CheckResult("network", "unavailable", "Both IPv4 and IPv6 kernel socket table reads failed")
        val rows = (v4.stdout + "\n" + v6.stdout).lineSequence().filter { line ->
            val columns = line.trim().split(Regex("\\s+")); columns.size >= 8 && columns[7] == uid.toString()
        }.take(MAX_ITEMS).map { line ->
            val fields = line.trim().split(Regex("\\s+")); "${fields[0]} local=${fields[1]} remote=${fields[2]} state=${fields[3]} uid=$uid"
        }.toList()
        val scope = if (isScopePersisted()) "an owned pinned-IP firewall ownership record exists (this does not prove installed rules remain effective)" else "no owned pinned-IP firewall ownership record exists"
        val status = if (v4.exitCode == 0 && v6.exitCode == 0) "complete" else "partial"
        val limitations = if (status == "partial") " One or more address-family socket table reads failed; evidence is partial." else ""
        return CheckResult("network", status, "Observed ${rows.size} bounded kernel socket rows for UID $uid; $scope.$limitations Scope pins resolved destination IPs, not hostname/TLS identity. Shared/CDN IPs may serve other hosts; proxies or other-UID mediation and isolated services may bypass UID accounting. Root-mediated/adversarial rooted code is not contained. TLS decryption was not performed.\n${rows.joinToString("\n")}")
    }

    private fun screenshots(observation: Observation?): CheckResult {
        val secure = observation?.nodes?.any { it.password } == true
        val screenshot = observation?.screenshotPath?.let(::File)
        val privateRoot = app.filesDir.canonicalFile
        val artifact = screenshot?.canonicalFile
        val inPrivateStorage = artifact != null && artifact.path.startsWith(privateRoot.path + File.separator)
        val length = artifact?.length() ?: 0L
        val actual = inPrivateStorage && artifact!!.isFile && length in 1..MAX_ARTIFACT_BYTES
        val status = if (actual) "complete" else "unavailable"
        return CheckResult("screenshots", status, "Screenshot artifact ${if (actual) "exists in app-private storage ($length bytes)" else "was not supplied, missing, outside app-private storage, or exceeds the size bound"}; observed password field=$secure; Android package metadata does not expose per-window FLAG_SECURE status, so secure-window coverage is unknown. Screenshot exposure is not automatically a vulnerability; only an actual reviewed image can establish visible content.", artifacts = if (actual) listOf(artifact!!.path) else emptyList())
    }

    private fun coverage(): CheckResult = CheckResult(
        "coverage", "incomplete",
        "Supported evidence: installed manifest metadata, bounded root-only file-path presence, bounded process logs, UID socket metadata, and supplied screenshot artifact. Explicitly unsupported/unverified: deep code analysis; runtime TLS/crypto hooks; decrypted network traffic; hostname identity beyond resolved IP pins; cross-account/business-logic authorization; exhaustive UI flows; per-window FLAG_SECURE coverage; per-domain custom Network Security Config cleartext rules. No live target assessment or clean bill of health is implied. Root-mediated connectivity, shared/CDN addresses, proxies/other-UID mediation, isolated-process UID ambiguity, and hostile rooted code are limitations."
    )

    @Suppress("DEPRECATION")
    private fun packageInfo(packageName: String): PackageInfo = if (Build.VERSION.SDK_INT >= 33) {
        app.packageManager.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong() or PackageManager.GET_ACTIVITIES.toLong() or PackageManager.GET_SERVICES.toLong() or PackageManager.GET_RECEIVERS.toLong() or PackageManager.GET_PROVIDERS.toLong()))
    } else {
        app.packageManager.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS or PackageManager.GET_ACTIVITIES or PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS or PackageManager.GET_PROVIDERS)
    }

    @Suppress("DEPRECATION")
    private fun versionCode(pkg: PackageInfo): Long = if (Build.VERSION.SDK_INT >= 28) pkg.longVersionCode else pkg.versionCode.toLong()

    private fun exportedComponents(pkg: PackageInfo): List<Pair<String, String>> = buildList {
        pkg.activities.orEmpty().filter { it.exported }.forEach { add("activity" to it.name) }
        pkg.services.orEmpty().filter { it.exported }.forEach { add("service" to it.name) }
        pkg.receivers.orEmpty().filter { it.exported }.forEach { add("receiver" to it.name) }
        pkg.providers.orEmpty().filter { it.exported }.forEach { add("provider" to it.name) }
    }

    private fun finding(id: String, title: String, severity: String, evidence: String) = Finding(id, title, severity, "medium", evidence, "Requires local access or relevant platform/app configuration; no ordinary-user exploit was demonstrated.", "Review exposure against intended app behavior and apply least privilege.")
    private fun safeMessage(e: Exception): String = redactor.redact((e.message ?: e.javaClass.simpleName).take(300))
    private fun isScopePersisted(): Boolean = app.getSharedPreferences("security_agent_firewall", Context.MODE_PRIVATE).contains("owned_scope")

    companion object {
        private const val MAX_ITEMS = 100
        private const val MAX_TEXT = 12_000
        private const val MAX_ARTIFACT_BYTES = 20L * 1024L * 1024L
        private const val ANDROID_PER_USER_RANGE = 100_000
    }
}
