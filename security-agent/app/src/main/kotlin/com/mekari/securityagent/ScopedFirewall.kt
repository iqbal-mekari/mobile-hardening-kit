package com.mekari.securityagent

import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Process
import org.json.JSONArray
import org.json.JSONObject
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.security.MessageDigest
import java.util.Locale

/** Restricts target-UID direct IP destinations. This pins IPs, not hostname/TLS identity. */
internal class ScopedFirewall(context: Context, private val root: RootShell) {
    private val app = context.applicationContext
    private val prefs = app.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    @Synchronized
    fun enforce(config: SessionConfig): String {
        synchronized(GLOBAL_LOCK) {
            check(prefs.getString(KEY_STATE, null) == null) { "An owned network restriction already exists; recover it before starting another session" }
            val info = app.packageManager.getApplicationInfo(config.targetPackage, 0)
            val uid = info.uid
            validateUid(config.targetPackage, uid)
            require(config.allowedHosts.isNotEmpty() && config.allowedHosts.size <= 32) { "Between 1 and 32 exact hosts are required" }
            val addresses = resolve(config.allowedHosts)
            check(addresses.isNotEmpty()) { "No allowed destination addresses resolved" }
            var state = OwnedState(config.targetPackage, uid, newChain(), addresses, emptySet())
            check(root.forceStopPackage(config.targetPackage).exitCode == 0) { "Unable to stop target before applying network scope" }
            persist(state)
            try {
                for ((binary, family) in listOf("iptables" to "4", "ip6tables" to "6")) {
                    val output = root.run("$binary -S OUTPUT")
                    check(output.exitCode == 0) { "$binary OUTPUT chain is unavailable" }
                    val c = state.chain + family
                    val existing = root.run("$binary -S ${RootShell.quote(c)}")
                    check(isMissingChain(existing)) { "$binary owned-chain name is occupied or cannot be inspected" }
                    val reservedState = state.copy(families = state.families + family)
                    persist(reservedState)
                    state = reservedState
                    val created = root.run("$binary -N ${RootShell.quote(c)}")
                    if (created.exitCode != 0) {
                        state = state.copy(families = state.families - family)
                        persist(state)
                        throw IllegalStateException("$binary chain creation failed (${created.exitCode})")
                    }
                    val familyAddresses = addresses.filter { if (family == "4") it is Inet4Address else it is Inet6Address }
                    for (address in familyAddresses) checked("$binary -A ${RootShell.quote(c)} -m owner --uid-owner ${RootShell.quote(state.uid.toString())} -d ${RootShell.quote(address.hostAddress.substringBefore('%'))} -j ACCEPT")
                    checked("$binary -A ${RootShell.quote(c)} -m owner --uid-owner ${RootShell.quote(state.uid.toString())} -j REJECT")
                    checked("$binary -I OUTPUT 1 -m owner --uid-owner ${RootShell.quote(state.uid.toString())} -j ${RootShell.quote(c)}")
                }
                return "Pinned-IP scope active for UID $uid; hostnames resolve to destination IPs, not hostname/TLS identity. Shared/CDN IPs may serve other hosts; proxies, other-UID mediation, isolated services, and hostile/rooted code are limitations."
            } catch (e: Exception) {
                val outcome = remove(state, stopFirst = false)
                if (outcome.errors.isEmpty()) clearPersisted() else throw IllegalStateException("Firewall setup failed and rollback was incomplete: ${outcome.errors.joinToString()}", e)
                throw IllegalStateException("Unable to establish complete IPv4/IPv6 target scope: ${e.message}", e)
            }
        }
    }

    @Synchronized
    fun release(): String = synchronized(GLOBAL_LOCK) {
        val raw = prefs.getString(KEY_STATE, null) ?: return@synchronized "No owned firewall scope"
        val state = try { decode(raw) } catch (e: Exception) { throw IllegalStateException("Persisted firewall ownership state is invalid; rules retained", e) }
        val outcome = remove(state, stopFirst = true)
        if (outcome.errors.isNotEmpty()) throw IllegalStateException("Unable to safely release owned firewall scope: ${outcome.errors.joinToString()}${outcome.warnings.joinToString(prefix = "; warnings: ")}")
        clearPersisted()
        val warning = outcome.warnings.takeIf { it.isNotEmpty() }?.joinToString(prefix = "; cleanup warning: ") ?: ""
        "Owned firewall chains removed for ${state.packageName}; unrelated rules preserved$warning"
    }

    /** Explicit stale cleanup only: caller must hold the gateway lease lock and confirm no live session. */
    @Synchronized
    fun recoverStale(): String = release()

    private fun validateUid(packageName: String, uid: Int) {
        require(uid >= FIRST_APPLICATION_UID && uid != Process.myUid()) { "System, controller, or shared UID target is forbidden" }
        require(Process.myUid() / ANDROID_PER_USER_RANGE == 0 && uid / ANDROID_PER_USER_RANGE == 0) { "Firewall enforcement supports owner-user targets only; force-stop helper is pinned to user 0" }
        val packages = app.packageManager.getPackagesForUid(uid)?.toSet().orEmpty()
        require(packages.size == 1 && packages.single() == packageName) { "Target UID is shared; cannot enforce isolated target scope" }
        val info = app.packageManager.getApplicationInfo(packageName, 0)
        require(info.flags and ApplicationInfo.FLAG_SYSTEM == 0) { "System target is forbidden" }
    }

    private fun resolve(hosts: List<String>): List<InetAddress> {
        val output = linkedMapOf<String, InetAddress>()
        for (input in hosts) {
            validateHostInput(input)
            val host = input
            val values = try { InetAddress.getAllByName(host) } catch (e: Exception) { throw IllegalArgumentException("Unable to resolve configured host", e) }
            require(values.isNotEmpty()) { "Configured host has no address" }
            for (address in values) {
                require(!address.isAnyLocalAddress && !address.isMulticastAddress && !address.isLoopbackAddress && !address.isLinkLocalAddress && address.hostAddress != "255.255.255.255") { "Wildcard, loopback, link-local, broadcast, and multicast destinations are forbidden" }
                val key = address.hostAddress.lowercase(Locale.ROOT)
                if (key !in output) require(output.size < MAX_RESOLVED_ADDRESSES) { "Configured hosts resolve to too many destination addresses" }
                output[key] = address
            }
        }
        return output.values.toList()
    }

    private fun newChain(): String = "SA" + java.util.UUID.randomUUID().toString().replace("-", "").take(20).uppercase(Locale.ROOT)

    private fun checked(command: String) {
        val result = root.run(command)
        check(result.exitCode == 0) { "Firewall command failed (${result.exitCode})" }
    }
    private fun isMissingChain(result: RootResult): Boolean =
        result.exitCode != 0 && result.stderr.contains("No chain/target/match by that name", ignoreCase = true)

    private fun remove(state: OwnedState, stopFirst: Boolean): CleanupOutcome {
        val errors = mutableListOf<String>()
        val warnings = mutableListOf<String>()
        if (stopFirst) {
            val before = try {
                app.packageManager.getApplicationInfo(state.packageName, 0)
            } catch (_: android.content.pm.PackageManager.NameNotFoundException) {
                null
            } catch (e: Exception) {
                return CleanupOutcome(listOf("cannot identify persisted target; owned scope retained: ${e.message}"), warnings)
            }
            if (before == null || before.uid != state.uid) {
                warnings += "Original package is absent or no longer owns UID ${state.uid}; replacement was not force-stopped"
            } else {
                val packages = try {
                    app.packageManager.getPackagesForUid(state.uid)?.toSet().orEmpty()
                } catch (e: Exception) {
                    return CleanupOutcome(listOf("cannot verify target UID ownership; owned scope retained: ${e.message}"), warnings)
                }
                if (before.flags and ApplicationInfo.FLAG_SYSTEM != 0 || packages != setOf(state.packageName)) {
                    warnings += "Target UID is now system/shared; force-stop skipped and only owned firewall rules will be removed"
                } else {
                    val stopped = try { root.forceStopPackage(state.packageName) } catch (e: Exception) {
                        return CleanupOutcome(listOf("target force-stop failed; owned scope retained: ${e.message}"), warnings)
                    }
                    if (stopped.exitCode != 0) {
                        val after = try {
                            app.packageManager.getApplicationInfo(state.packageName, 0)
                        } catch (_: android.content.pm.PackageManager.NameNotFoundException) {
                            null
                        } catch (e: Exception) {
                            return CleanupOutcome(listOf("force-stop failed and target identity is uncertain; owned scope retained: ${e.message}"), warnings)
                        }
                        if (after?.uid == state.uid) return CleanupOutcome(listOf("target force-stop failed; owned scope retained"), warnings)
                        warnings += "Original package changed during force-stop; no replacement was stopped"
                    }
                }
            }
        }
        for (family in state.families) {
            val binary = if (family == "4") "iptables" else "ip6tables"
            val c = state.chain + family
            val jump = "$binary -D OUTPUT -m owner --uid-owner ${RootShell.quote(state.uid.toString())} -j ${RootShell.quote(c)}"
            try {
                val output = root.run("$binary -S OUTPUT")
                if (output.exitCode != 0) {
                    errors.add("$binary OUTPUT rules could not be inspected")
                    continue
                }
                val hasJump = output.stdout.lineSequence().any { it.contains("-m owner --uid-owner ${state.uid}") && it.endsWith("-j $c") }
                if (hasJump) checked(jump)
                val remaining = root.run("$binary -S OUTPUT")
                if (remaining.exitCode != 0 || remaining.stdout.lineSequence().any { it.contains("-m owner --uid-owner ${state.uid}") && it.endsWith("-j $c") }) {
                    errors.add("$binary owned jump could not be removed")
                    continue
                }
                val chainExists = root.run("$binary -S ${RootShell.quote(c)}")
                if (chainExists.exitCode == 0) {
                    checked("$binary -F ${RootShell.quote(c)}")
                    checked("$binary -X ${RootShell.quote(c)}")
                } else if (!isMissingChain(chainExists)) {
                    errors.add("$binary owned chain could not be inspected")
                }
            } catch (e: Exception) {
                errors.add("$binary owned rules: ${e.message}")
            }
        }
        return CleanupOutcome(errors, warnings)
    }

    private fun persist(s: OwnedState) {
        val json = JSONObject()
            .put("package", s.packageName)
            .put("uid", s.uid)
            .put("chain", s.chain)
            .put("addresses", JSONArray(s.addresses.map { it.hostAddress.substringBefore('%') }))
            .put("families", JSONArray(s.families.toList()))
        check(prefs.edit().putString(KEY_STATE, json.toString()).commit()) { "Could not persist firewall ownership state" }
    }

    private fun decode(raw: String): OwnedState {
        val json = JSONObject(raw)
        val pkg = json.getString("package")
        val uid = json.getInt("uid")
        val chain = json.getString("chain")
        require(chain.matches(Regex("SA[0-9A-F]{20}"))) { "Persisted chain identifier is invalid" }
        val addressesJson = json.getJSONArray("addresses")
        val addresses = (0 until addressesJson.length()).map { InetAddress.getByName(addressesJson.getString(it)) }
        val familiesJson = json.getJSONArray("families")
        val families = (0 until familiesJson.length()).map { familiesJson.getString(it) }.toSet()
        require(families.all { it == "4" || it == "6" } && families.size == familiesJson.length()) { "Persisted address-family ownership is invalid" }
        return OwnedState(pkg, uid, chain, addresses, families)
    }

    private fun clearPersisted() { check(prefs.edit().remove(KEY_STATE).commit()) { "Could not clear firewall ownership state" } }

    private data class OwnedState(
        val packageName: String,
        val uid: Int,
        val chain: String,
        val addresses: List<InetAddress>,
        val families: Set<String>
    )
    private data class CleanupOutcome(val errors: List<String>, val warnings: List<String>)
    companion object {
        internal fun validateHostInput(host: String) {
            require(host.length in 1..253 && !host.startsWith('.') && !host.endsWith('.') && !host.contains("..")) { "Invalid exact host" }
            require(!host.contains('*') && !host.contains('/') && !host.contains('@') && !host.contains("://") && !host.any { it.code <= 0x20 || it.code == 0x7f }) { "Invalid exact host" }
        }
        private const val PREFS = "security_agent_firewall"
        private const val KEY_STATE = "owned_scope"
        private const val FIRST_APPLICATION_UID = 10_000
        private const val MAX_RESOLVED_ADDRESSES = 64
        private const val ANDROID_PER_USER_RANGE = 100_000
        private val GLOBAL_LOCK = Any()
    }
}
