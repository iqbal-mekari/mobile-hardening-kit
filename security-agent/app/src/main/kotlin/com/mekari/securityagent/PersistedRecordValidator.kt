package com.mekari.securityagent

import org.json.JSONArray
import org.json.JSONObject

/** Validates persisted values before repository decoding or state reuse. */
internal object PersistedRecordValidator {
    private val fields = setOf("id", "config", "status", "startedAt", "updatedAt", "message", "steps", "checks", "findings", "visitedScreens")
    private val requiredConfigFields = setOf("targetPackage", "endpoint", "model", "allowedHosts", "maxSteps", "screenshotsToCloud", "cloudConsent")
    private val optionalConfigFields = setOf("provider", "liveAdvisories", "advisoryEndpoint")
    private val findingFields = setOf("id", "title", "severity", "confidence", "evidence", "attackerPrerequisite", "remediation", "phase")
    private val actionFields = setOf("kind", "nodeId", "text", "credentialId", "direction", "checkId", "reason")

    fun validate(json: String, expectedId: String) {
        require(expectedId.matches(Regex("[A-Za-z0-9-]{1,64}"))) { "Invalid assessment session ID" }
        require(json.length <= MAX_RECORD_CHARS) { "Assessment record exceeds persistence size limit" }
        val record = JSONObject(json)
        require(record.keys().asSequence().toSet() == fields) { "Assessment record has missing or unknown fields" }
        require(record.string("id") == expectedId) { "Assessment record ID does not match its file" }
        SessionStatus.valueOf(record.string("status"))
        record.number("startedAt"); record.number("updatedAt"); record.string("message")
        validateConfig(record.get("config") as? JSONObject ?: throw IllegalArgumentException("Saved configuration is malformed"))
        validateSteps(record.array("steps"))
        validateChecks(record.array("checks"))
        validateFindings(record.array("findings"))
        val visited = record.array("visitedScreens")
        for (index in 0 until visited.length()) require(visited.get(index) is String) { "Visited screen entry is malformed" }
    }

    private fun validateConfig(config: JSONObject) {
        // Required keys must all be present; any other key must be a known optional one (unknown keys still rejected as tampering).
        val keys = config.keys().asSequence().toSet()
        require(keys.containsAll(requiredConfigFields) && (keys - requiredConfigFields).all { it in optionalConfigFields }) { "Saved configuration has missing or unknown fields" }
        config.string("targetPackage"); config.string("endpoint"); config.string("model")
        val hosts = config.array("allowedHosts")
        require(hosts.length() in 1..64)
        for (index in 0 until hosts.length()) require(hosts.get(index) is String) { "Allowed host is malformed" }
        require(config.number("maxSteps") in 1L..200L)
        config.boolean("screenshotsToCloud"); config.boolean("cloudConsent")
        if (config.has("provider")) ModelProvider.valueOf(config.string("provider"))
        if (config.has("liveAdvisories")) config.boolean("liveAdvisories")
        if (config.has("advisoryEndpoint")) config.string("advisoryEndpoint")
    }

    private fun validateSteps(steps: JSONArray) {
        require(steps.length() <= MAX_ITEMS)
        steps.forEachObject { step ->
            require(step.keys().asSequence().toSet() == setOf("index", "at", "action", "packageName", "outcome", "success"))
            require(step.number("index") in 1L..200L); step.number("at"); step.string("packageName"); step.string("outcome"); step.boolean("success")
            val action = step.get("action") as? JSONObject ?: throw IllegalArgumentException("Saved action is malformed")
            require(action.keys().asSequence().toSet() == actionFields)
            ActionKind.valueOf(action.string("kind"))
            actionFields.filter { it != "kind" }.forEach { action.string(it) }
        }
    }

    private fun validateChecks(checks: JSONArray) {
        require(checks.length() <= MAX_ITEMS)
        checks.forEachObject { check ->
            require(check.keys().asSequence().toSet() == setOf("checkId", "status", "summary", "findings", "artifacts"))
            require(check.string("checkId") in ActionPolicy.supportedChecks)
            check.string("status"); check.string("summary")
            validateFindings(check.array("findings"))
            val artifacts = check.array("artifacts")
            for (index in 0 until artifacts.length()) require(artifacts.get(index) is String) { "Check artifact is malformed" }
        }
    }

    private fun validateFindings(findings: JSONArray) {
        require(findings.length() <= MAX_ITEMS)
        findings.forEachObject { finding ->
            require(finding.keys().asSequence().toSet() == findingFields)
            findingFields.forEach { finding.string(it) }
        }
    }

    private fun JSONObject.string(key: String): String = get(key) as? String ?: throw IllegalArgumentException("Persisted field '$key' is not a string")
    private fun JSONObject.boolean(key: String): Boolean = get(key) as? Boolean ?: throw IllegalArgumentException("Persisted field '$key' is not a boolean")
    private fun JSONObject.number(key: String): Long {
        val value = get(key)
        require(value is Int || value is Long) { "Persisted field '$key' is not an integer" }
        return (value as Number).toLong()
    }
    private fun JSONObject.array(key: String): JSONArray = get(key) as? JSONArray ?: throw IllegalArgumentException("Persisted field '$key' is not an array")
    private inline fun JSONArray.forEachObject(action: (JSONObject) -> Unit) {
        for (index in 0 until length()) action(get(index) as? JSONObject ?: throw IllegalArgumentException("Persisted object array entry is malformed"))
    }

    private const val MAX_ITEMS = 100_000
    private const val MAX_RECORD_CHARS = 32 * 1024 * 1024
}
