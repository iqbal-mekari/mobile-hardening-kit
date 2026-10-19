package com.mekari.securityagent

import java.net.URI

/** Local allow-list for model proposals; no model-provided string is an executable command. */
object ActionPolicy {
    val supportedChecks = setOf("manifest", "storage", "logs", "network", "screenshots", "coverage")
    val credentialIds = setOf("username", "password")
    data class Decision(val accepted: Boolean, val reason: String = "")

    fun validate(action: AgentAction, observation: Observation, config: SessionConfig, knownCredentialIds: Set<String> = credentialIds): Decision {
        if (observation.error != null) return Decision(false, "Observation unavailable; refresh required")
        if (observation.packageName != config.targetPackage) return Decision(false, "Current screen is outside the configured target")
        if (System.currentTimeMillis() - observation.capturedAt !in 0..30_000) return Decision(false, "Observation is stale; refresh required")
        if (action.nodeId.length > 128 || action.text.length > 2048 || action.reason.length > 512) return Decision(false, "Action exceeds permitted bounds")
        val node = if (action.nodeId.isEmpty()) null else observation.nodes.firstOrNull { it.id == action.nodeId }
        if (action.nodeId.isNotEmpty() && (node == null || node.packageName != config.targetPackage)) return Decision(false, "Action refers to a missing or out-of-scope node")
        if (node != null && node.packageName != config.targetPackage) return Decision(false, "Action node is outside the configured target")
        when (action.kind) {
            ActionKind.TAP -> if (node?.clickable != true) return Decision(false, "Tap requires a current clickable target node")
            ActionKind.TYPE_TEXT -> if (node?.editable != true || node.password || action.credentialId.isNotEmpty()) return Decision(false, "Text entry requires a non-password editable target")
            ActionKind.ENTER_CREDENTIAL -> if (node?.editable != true || action.credentialId !in knownCredentialIds || action.text.isNotEmpty() || (action.credentialId == "password") != (node?.password == true)) return Decision(false, "Credential entry requires a matching known credential reference and editable target")
            ActionKind.SCROLL -> if (action.direction !in setOf("up", "down")) return Decision(false, "Unsupported scroll direction")
            ActionKind.WAIT -> if (action.text.isNotEmpty() || action.nodeId.isNotEmpty() || action.reason.toLongOrNull()?.let { it in 0..5000 } != true) return Decision(false, "Wait duration must be 0–5000 milliseconds in reason")
            ActionKind.RUN_CHECK -> if (action.checkId !in supportedChecks || action.nodeId.isNotEmpty() || action.text.isNotEmpty()) return Decision(false, "Unsupported check")
            ActionKind.REPORT_HYPOTHESIS -> if (action.nodeId.isNotEmpty() || action.text.isBlank() || action.reason.isBlank()) return Decision(false, "Hypothesis requires a summary and supporting observation")
            ActionKind.BACK, ActionKind.FINISH, ActionKind.REQUEST_HELP -> if (action.nodeId.isNotEmpty() || action.text.isNotEmpty() || action.credentialId.isNotEmpty() || action.direction.isNotEmpty() || action.checkId.isNotEmpty()) return Decision(false, "Action contains irrelevant fields")
        }
        if (action.kind != ActionKind.RUN_CHECK && action.checkId.isNotEmpty()) return Decision(false, "Check identifier is irrelevant")
        if (action.kind != ActionKind.SCROLL && action.direction.isNotEmpty()) return Decision(false, "Direction is irrelevant")
        if (action.kind != ActionKind.ENTER_CREDENTIAL && action.credentialId.isNotEmpty()) return Decision(false, "Credential identifier is irrelevant")
        if (action.kind !in setOf(ActionKind.TYPE_TEXT, ActionKind.ENTER_CREDENTIAL, ActionKind.REPORT_HYPOTHESIS) && action.text.isNotEmpty()) return Decision(false, "Text is irrelevant")
        if (action.kind !in setOf(ActionKind.WAIT, ActionKind.REQUEST_HELP, ActionKind.REPORT_HYPOTHESIS) && action.reason.isNotEmpty()) return Decision(false, "Reason is irrelevant")
        return Decision(true)
    }

    fun validateConfig(config: SessionConfig): String? {
        val uri = runCatching { URI(config.endpoint) }.getOrNull() ?: return "Cloud endpoint is invalid"
        if (uri.scheme != "https" || uri.host.isNullOrBlank() || uri.userInfo != null || uri.fragment != null || uri.query != null) return "Cloud endpoint must be an HTTPS URI without user information, query, or fragment"
        if (config.targetPackage.isBlank() || config.targetPackage.length > 255) return "Target package is invalid"
        if (config.model.isBlank() || config.model.length > 128 || config.maxSteps !in 1..200) return "Model or step limit is invalid"
        if (config.allowedHosts.isEmpty() || config.allowedHosts.size > 64 || config.allowedHosts.any { it.isBlank() || it.length > 253 || it.contains('*') || it.contains('/') || it.contains('@') }) return "Allowed hosts must be exact hostnames"
        if (config.liveAdvisories) {
            if (config.advisoryEndpoint.length > 2048) return "Advisory endpoint is too long"
            val advisory = runCatching { URI(config.advisoryEndpoint) }.getOrNull() ?: return "Advisory endpoint is invalid"
            // A feed may legitimately carry query parameters, unlike the model endpoint; userinfo and fragments are still rejected.
            if (advisory.scheme != "https" || advisory.host.isNullOrBlank() || advisory.userInfo != null || advisory.fragment != null) return "Advisory endpoint must be an HTTPS URI without user information or fragment"
        } else if (config.advisoryEndpoint.isNotEmpty()) {
            return "Advisory endpoint must be empty when live advisories are disabled"
        }
        return null
    }
}
