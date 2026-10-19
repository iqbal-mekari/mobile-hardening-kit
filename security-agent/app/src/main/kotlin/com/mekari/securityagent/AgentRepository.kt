package com.mekari.securityagent

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream

class AgentRepository(private val context: Context) : SessionStore {
    private val base = File(context.filesDir, "assessment").apply { mkdirs() }
    private val sessions = File(base, "sessions").apply { mkdirs() }
    private val configFile = File(base, "config.json")
    private val vault = SecretVault(base)

    @Synchronized fun saveConfig(config: SessionConfig) {
        ActionPolicy.validateConfig(config)?.let { throw IllegalArgumentException(it) }
        atomicWrite(configFile, configJson(config).toString())
    }
    @Synchronized fun loadConfig(): SessionConfig? = if (!configFile.exists()) null else runCatching { parseConfig(JSONObject(configFile.readText())) }.getOrElse { throw IllegalStateException("Saved configuration is corrupt") }
    @Synchronized fun setSecret(id: String, value: String) = vault.set(id, value)
    @Synchronized override fun getSecret(id: String): String? = vault.get(id)
    @Synchronized fun createSession(config: SessionConfig): SessionRecord = SessionRecord(newSessionId(), config).also { saveSession(it) }
    @Synchronized override fun saveSession(record: SessionRecord) {
        require(record.id.matches(Regex("[A-Za-z0-9-]{1,64}"))) { "Invalid assessment session ID" }
        ActionPolicy.validateConfig(record.config)?.let { throw IllegalArgumentException(it) }
        val clean = Redactor.sanitizeRecord(record, secretValues())
        val serialized = encode(clean).toString()
        require(serialized.toByteArray(Charsets.UTF_8).size <= MAX_RECORD_BYTES) { "Assessment record exceeds persistence size limit" }
        atomicWrite(sessionFile(clean.id), serialized)
    }
    @Synchronized override fun readSession(id: String): SessionRecord? {
        require(id.matches(Regex("[A-Za-z0-9-]{1,64}")))
        val file = sessionFile(id); if (!file.exists()) return null
        require(file.length() in 1..MAX_RECORD_BYTES.toLong()) { "Assessment record exceeds persistence size limit" }
        return try {
            val raw = file.readText()
            PersistedRecordValidator.validate(raw, id)
            val decoded = decode(JSONObject(raw))
            Redactor.sanitizeRecord(decoded, secretValues())
        } catch (_: Exception) { throw IllegalStateException("Saved assessment record is corrupt or secret protection is unavailable") }

    }
    @Synchronized fun latestSession(): SessionRecord? {
        val files = sessions.listFiles()?.filter { it.isFile && it.name.endsWith(".json") } ?: return null
        val file = files.maxByOrNull { it.lastModified() } ?: return null
        return readSession(file.name.removeSuffix(".json"))
    }
    fun report(record: SessionRecord): String = ReportRenderer.render(Redactor.sanitizeRecord(record, secretValues()))

    private fun secretValues() = listOf("cloud_api_key", "username", "password").mapNotNull { vault.get(it) }
    private fun atomicWrite(target: File, value: String) {
        val temp = File.createTempFile("security-agent-", ".tmp", target.parentFile)
        try { FileOutputStream(temp).use { it.write(value.toByteArray(Charsets.UTF_8)); it.fd.sync() }; if (!temp.renameTo(target)) throw IllegalStateException("Atomic persistence failed") }
        finally { if (temp.exists()) temp.delete() }
    }
    private fun sessionFile(id: String): File {
        require(id.matches(Regex("[A-Za-z0-9-]{1,64}"))) { "Invalid assessment session ID" }
        return File(sessions, "$id.json")
    }
    private fun configJson(c: SessionConfig) = JSONObject().put("targetPackage", c.targetPackage).put("endpoint", c.endpoint).put("model", c.model).put("allowedHosts", JSONArray(c.allowedHosts)).put("maxSteps", c.maxSteps).put("screenshotsToCloud", c.screenshotsToCloud).put("cloudConsent", c.cloudConsent).put("provider", c.provider.name).put("liveAdvisories", c.liveAdvisories).put("advisoryEndpoint", c.advisoryEndpoint)
    private fun parseConfig(o: JSONObject): SessionConfig {
        // provider/liveAdvisories/advisoryEndpoint read tolerantly so configs written before they existed still load.
        val provider = runCatching { ModelProvider.valueOf(o.optString("provider", ModelProvider.OPENAI.name)) }.getOrDefault(ModelProvider.OPENAI)
        val config = SessionConfig(o.getString("targetPackage"), o.getString("endpoint"), o.getString("model"), o.getJSONArray("allowedHosts").let { a -> (0 until a.length()).map { a.getString(it) } }, o.getInt("maxSteps"), o.getBoolean("screenshotsToCloud"), o.getBoolean("cloudConsent"), provider, o.optBoolean("liveAdvisories", false), o.optString("advisoryEndpoint", ""))
        ActionPolicy.validateConfig(config)?.let { throw IllegalArgumentException(it) }
        return config
    }
    private fun encode(r: SessionRecord): JSONObject = JSONObject().put("id",r.id).put("config",configJson(r.config)).put("status",r.status.name).put("startedAt",r.startedAt).put("updatedAt",r.updatedAt).put("message",r.message).put("steps",JSONArray().apply { r.steps.forEach { s -> put(JSONObject().put("index",s.index).put("at",s.at).put("action",actionJson(s.action)).put("packageName",s.packageName).put("outcome",s.outcome).put("success",s.success)) } }).put("checks",JSONArray().apply { r.checks.forEach { put(checkJson(it)) } }).put("findings",JSONArray().apply { r.findings.forEach { put(findingJson(it)) } }).put("visitedScreens",JSONArray(r.visitedScreens))
    private fun decode(o: JSONObject): SessionRecord = SessionRecord(o.getString("id"),parseConfig(o.getJSONObject("config")),SessionStatus.valueOf(o.getString("status")),o.getLong("startedAt"),o.getLong("updatedAt"),o.getString("message"),array(o,"steps"){v->StepRecord(v.getInt("index"),v.getLong("at"),parseAction(v.getJSONObject("action")),v.getString("packageName"),v.getString("outcome"),v.getBoolean("success"))},array(o,"checks"){parseCheck(it)},array(o,"findings"){parseFinding(it)},strings(o,"visitedScreens"))
    private fun actionJson(a: AgentAction)=JSONObject().put("kind",a.kind.name).put("nodeId",a.nodeId).put("text",a.text).put("credentialId",a.credentialId).put("direction",a.direction).put("checkId",a.checkId).put("reason",a.reason)
    private fun parseAction(o: JSONObject)=AgentAction(ActionKind.valueOf(o.getString("kind")),o.getString("nodeId"),o.getString("text"),o.getString("credentialId"),o.getString("direction"),o.getString("checkId"),o.getString("reason"))
    private fun findingJson(f: Finding)=JSONObject().put("id",f.id).put("title",f.title).put("severity",f.severity).put("confidence",f.confidence).put("evidence",f.evidence).put("attackerPrerequisite",f.attackerPrerequisite).put("remediation",f.remediation).put("phase",f.phase)
    private fun parseFinding(o: JSONObject)=Finding(o.getString("id"),o.getString("title"),o.getString("severity"),o.getString("confidence"),o.getString("evidence"),o.getString("attackerPrerequisite"),o.getString("remediation"),o.getString("phase"))
    private fun checkJson(c: CheckResult)=JSONObject().put("checkId",c.checkId).put("status",c.status).put("summary",c.summary).put("findings",JSONArray().apply{c.findings.forEach{put(findingJson(it))}}).put("artifacts",JSONArray(c.artifacts))
    private fun parseCheck(o: JSONObject)=CheckResult(o.getString("checkId"),o.getString("status"),o.getString("summary"),array(o,"findings"){parseFinding(it)},strings(o,"artifacts"))
    private fun <T> array(o: JSONObject,key:String,convert:(JSONObject)->T):List<T> { val a=o.getJSONArray(key); require(a.length()<=100_000); return (0 until a.length()).map { convert(a.getJSONObject(it)) } }
    private fun strings(o: JSONObject,key:String):List<String>{val a=o.getJSONArray(key);require(a.length()<=100_000);return (0 until a.length()).map{a.getString(it)}}
    private companion object { const val MAX_RECORD_BYTES = 32 * 1024 * 1024 }
}
