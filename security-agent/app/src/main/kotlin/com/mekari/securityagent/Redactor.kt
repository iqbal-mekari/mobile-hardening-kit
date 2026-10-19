package com.mekari.securityagent

object Redactor {
    private val genericPatterns = listOf(
        Regex("(?i)(bearer\\s+)[A-Za-z0-9._~+/-]+=*"),
        Regex("(?i)(api[_-]?key|token|password|secret)(\\s*[:=]\\s*)[^\\s,;]+"),
        Regex("(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}"),
        Regex("(?<!\\d)(?:\\+?\\d[ -]?){8,15}(?!\\d)")
    )
    fun redact(value: String, secrets: Collection<String> = emptyList()): String {
        var result = redactSecrets(value, secrets)
        genericPatterns.forEach { pattern -> result = pattern.replace(result) { match ->
            when (match.groupValues.size) { 3 -> match.groupValues[1] + "[REDACTED]"; else -> "[REDACTED]" }
        } }
        return result.take(4096)
    }
    // App-generated artifact paths skip the generic patterns, which mangle UUID filenames that resemble phone numbers.
    private fun redactSecrets(value: String, secrets: Collection<String>): String {
        var result = value
        secrets.filter { it.isNotEmpty() }.distinct().forEach { secret -> result = result.replace(secret, "[REDACTED]", ignoreCase = false) }
        return result
    }
    fun sanitizeObservation(observation: Observation, secrets: Collection<String>): Observation = observation.copy(
        nodes = observation.nodes.map { n -> n.copy(
            text = if (n.password) "[password field]" else redact(n.text, secrets),
            description = redact(n.description, secrets), resourceId = redact(n.resourceId, secrets),
            className = redact(n.className, secrets), packageName = redact(n.packageName, secrets), bounds = redact(n.bounds, secrets)
        ) }, error = observation.error?.let { redact(it, secrets) }
    )
    fun sanitizeAction(action: AgentAction, secrets: Collection<String>): AgentAction = action.copy(
        text = redact(action.text, secrets), reason = redact(action.reason, secrets)
    )
    fun sanitizeRecord(record: SessionRecord, secrets: Collection<String>): SessionRecord = record.copy(
        message = redact(record.message, secrets),
        steps = record.steps.map { it.copy(action = sanitizeAction(it.action, secrets), outcome = redact(it.outcome, secrets)) },
        checks = record.checks.map { it.copy(summary = redact(it.summary, secrets), artifacts = it.artifacts.map { a -> redactSecrets(a, secrets) }, findings = it.findings.map { f -> sanitizeFinding(f, secrets) }) },
        findings = record.findings.map { sanitizeFinding(it, secrets) }, visitedScreens = record.visitedScreens.map { redact(it, secrets) }
    )
    private fun sanitizeFinding(f: Finding, secrets: Collection<String>) = f.copy(
        title = redact(f.title, secrets), evidence = redact(f.evidence, secrets), attackerPrerequisite = redact(f.attackerPrerequisite, secrets), remediation = redact(f.remediation, secrets)
    )
}
