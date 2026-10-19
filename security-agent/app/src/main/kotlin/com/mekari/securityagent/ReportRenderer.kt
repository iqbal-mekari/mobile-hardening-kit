package com.mekari.securityagent

import org.json.JSONArray
import org.json.JSONObject

object ReportRenderer {
    fun render(record: SessionRecord): String {
        val json = JSONObject().put("sessionId",record.id).put("targetPackage",record.config.targetPackage).put("endpointHost",runCatching{java.net.URI(record.config.endpoint).host}.getOrNull()).put("model",record.config.model).put("provider",record.config.provider.name).put("liveAdvisories",record.config.liveAdvisories).put("status",record.status.name).put("startedAt",record.startedAt).put("updatedAt",record.updatedAt).put("message",record.message).put("steps",JSONArray().apply{record.steps.forEach{put(JSONObject().put("index",it.index).put("at",it.at).put("kind",it.action.kind.name).put("outcome",it.outcome).put("success",it.success))}}).put("checks",JSONArray().apply{record.checks.forEach{put(JSONObject().put("checkId",it.checkId).put("status",it.status).put("summary",it.summary))}}).put("findings",JSONArray().apply{record.findings.forEach{put(JSONObject().put("id",it.id).put("title",it.title).put("severity",it.severity).put("confidence",it.confidence).put("evidence",it.evidence).put("attackerPrerequisite",it.attackerPrerequisite).put("remediation",it.remediation).put("phase",it.phase))}}).put("visitedScreens",JSONArray(record.visitedScreens))
        json.put("hypotheses", JSONArray().apply {
            record.steps.filter { it.action.kind == ActionKind.REPORT_HYPOTHESIS }.forEach { step ->
                put(JSONObject().put("summary", step.action.text).put("supportingObservation", step.action.reason).put("status", "unverified"))
            }
        })
            json.put("collectorArtifacts", JSONArray().apply {
                record.checks.forEach { check -> check.artifacts.forEach { artifact ->
                    put(JSONObject().put("checkId", check.checkId).put("artifact", artifact))
                } }
            })
        val safeJson = json.toString(2).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026").replace("`", "\\u0060")
        val markdown = buildString {
            appendLine("# Security assessment report"); appendLine(); appendLine("**Status:** ${record.status.name}"); appendLine("**Target package:** ${escape(record.config.targetPackage)}"); appendLine("**Model provider:** ${record.config.provider.name}; live advisories: ${record.config.liveAdvisories}"); appendLine("**Started:** ${record.startedAt}"); appendLine("**Updated:** ${record.updatedAt}"); appendLine("**Session message:** ${escape(record.message)}"); appendLine()
            appendLine("## Coverage and collectors"); appendLine()
            if (record.checks.isEmpty()) appendLine("No collector results are recorded; assessment coverage is incomplete.")
            record.checks.forEach { appendLine("- **${escape(it.checkId)} — ${escape(it.status)}:** ${escape(it.summary)}") }
            record.checks.filter { it.artifacts.isNotEmpty() }.forEach { check ->
                check.artifacts.forEach { appendLine("  - Artifact: ${escape(it)}") }
            }
            appendLine(); appendLine("## Observed screen fingerprints"); appendLine()
            if (record.visitedScreens.isEmpty()) appendLine("No target screen fingerprints were recorded; this is not an exhaustive UI coverage measure.")
            else {
                appendLine("Observed fingerprints are identifiers only and do not imply exhaustive UI coverage.")
                record.visitedScreens.forEach { appendLine("- `${escape(it)}`") }
            }
            appendLine(); appendLine("## Findings"); appendLine()
            if (record.findings.isEmpty()) appendLine("No findings were recorded. This is not evidence of a clean bill of health.")
            record.findings.forEach { appendLine("### ${escape(it.title)}"); appendLine("Severity: ${escape(it.severity)}; confidence: ${escape(it.confidence)}; phase: ${escape(it.phase)}"); appendLine("Evidence: ${escape(it.evidence)}"); appendLine("Attacker prerequisite: ${escape(it.attackerPrerequisite)}"); appendLine("Remediation: ${escape(it.remediation)}"); appendLine() }
            appendLine("## Model hypotheses — unverified"); appendLine()
            val hypotheses = record.steps.filter { it.action.kind == ActionKind.REPORT_HYPOTHESIS }
            if (hypotheses.isEmpty()) appendLine("No model hypotheses were submitted.")
            hypotheses.forEach { appendLine("- **${escape(it.action.text)}** — Supporting observation: ${escape(it.action.reason)} (unverified model hypothesis; not a deterministic finding).") }
            appendLine("## Action history"); appendLine(); record.steps.forEach { appendLine("- #${it.index} ${it.action.kind.name}: ${escape(it.outcome)} (success=${it.success})") }
            appendLine(); appendLine("## Machine-readable record"); appendLine(); appendLine("```json"); appendLine(safeJson); appendLine("```")
        }
        return markdown
    }
    private fun escape(s: String) = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\\", "\\\\").replace("`", "\\`").replace("*", "\\*").replace("_", "\\_").replace("[", "\\[").replace("]", "\\]").replace("|", "\\|").replace("\r", " ").replace("\n", " ")
}
