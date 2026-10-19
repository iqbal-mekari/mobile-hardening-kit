package com.mekari.securityagent

import android.accessibilityservice.AccessibilityService
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.provider.Settings
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import android.app.KeyguardManager
import android.os.PowerManager

/** Target-scoped UI access. Live AccessibilityNodeInfo values are never retained between calls. */
class AgentAccessibilityService : AccessibilityService() {
    override fun onServiceConnected() {
        super.onServiceConnected()
        connected = this
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) = Unit

    override fun onInterrupt() = Unit

    override fun onDestroy() {
        invalidate()
        connected = null
        super.onDestroy()
    }

    internal fun observeTarget(target: String): Observation {
        val keyguard = getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        val power = getSystemService(Context.POWER_SERVICE) as PowerManager
        if (!power.isInteractive || keyguard.isKeyguardLocked) {
            invalidate()
            return Observation("", emptyList(), error = "Device is locked or screen is off; user intervention required")
        }
        val root = rootInActiveWindow ?: run {
            invalidate()
            return Observation("", emptyList(), error = "Accessibility window is unavailable")
        }
        return try {
            val actual = root.packageName?.toString().orEmpty()
            if (actual != target) {
                invalidate()
                Observation(actual, emptyList(), error = "Target app is not the foreground package; user intervention required")
            } else {
                val token = nextSnapshotTimestamp()
                val nodes = ArrayList<UiNode>(MAX_NODES)
                if (!walk(root, target, "0", 0, nodes)) {
                    invalidate()
                    return Observation(actual, emptyList(), error = "Target UI changed during observation; observe again")
                }
                snapshot = Snapshot(target, token)
                Observation(actual, nodes, capturedAt = token)
            }
        } finally {
            root.recycle()
        }
    }
    internal fun isForegroundTarget(target: String): Boolean {
        if (isLocked()) return false
        val root = rootInActiveWindow ?: return false
        return try { root.packageName?.toString() == target } finally { root.recycle() }
    }

    internal fun act(action: AgentAction, observation: Observation, target: String, credential: String?): ActionResult {
        if (observation.error != null || observation.packageName != target) return ActionResult(false, "Observation is not a valid target-app snapshot")
        val known = snapshot
        if (known == null || known.target != target || known.timestamp != observation.capturedAt ||
            System.currentTimeMillis() - observation.capturedAt !in 0..MAX_OBSERVATION_AGE_MS
        ) return ActionResult(false, "Observation expired; observe the target again")
        if (isLocked()) return ActionResult(false, "Device is locked or screen is off; user intervention required")
        val root = rootInActiveWindow ?: return ActionResult(false, "Accessibility window is unavailable")
        return try {
            if (root.packageName?.toString() != target) return ActionResult(false, "Target app is not the foreground package; user intervention required")
            if (action.kind == ActionKind.BACK) {
                invalidate()
                return ActionResult(performGlobalAction(GLOBAL_ACTION_BACK), "Back action requested")
            }
            val expected = observation.nodes.firstOrNull { it.id == action.nodeId && it.packageName == target }
                ?: return ActionResult(false, "Target node was not part of the supplied observation")
            val path = parsePath(action.nodeId) ?: return ActionResult(false, "Invalid node identity")
            var node: AccessibilityNodeInfo = root
            for (index in path.drop(1)) {
                if (node.packageName?.toString() != target || index !in 0 until node.childCount) {
                    if (node !== root) node.recycle()
                    return ActionResult(false, "Target node is no longer available")
                }
                val child = node.getChild(index)
                if (child == null) {
                    if (node !== root) node.recycle()
                    return ActionResult(false, "Target node is no longer available")
                }
                if (node !== root) node.recycle()
                node = child
            }
            try {
                if (!node.refresh()) return ActionResult(false, "Target node is no longer attached to the accessibility window; observe again")
                val bounds = android.graphics.Rect().also(node::getBoundsInScreen)
                val currentText = if (node.isPassword) "" else node.text?.toString()?.take(MAX_TEXT).orEmpty()
                val currentDescription = if (node.isPassword) "" else node.contentDescription?.toString()?.take(MAX_TEXT).orEmpty()
                if (node.packageName?.toString() != target ||
                    node.className?.toString().orEmpty() != expected.className ||
                    node.viewIdResourceName.orEmpty() != expected.resourceId ||
                    node.isEditable != expected.editable || node.isPassword != expected.password ||
                    node.isClickable != expected.clickable ||
                    currentText != expected.text || currentDescription != expected.description ||
                    "${bounds.left},${bounds.top},${bounds.right},${bounds.bottom}" != expected.bounds
                ) return ActionResult(false, "Target node identity changed; observe again")
                invalidate()
                when (action.kind) {
                    ActionKind.TAP -> {
                        val performed = node.isClickable && node.performAction(AccessibilityNodeInfo.ACTION_CLICK)
                        ActionResult(performed, if (performed) "Accessibility click accepted by Android" else "Android refused the accessibility click; target state may have changed or stopped")
                    }
                    ActionKind.TYPE_TEXT, ActionKind.ENTER_CREDENTIAL -> {
                        if (!node.isEditable) return ActionResult(false, "Selected target node is not editable")
                        if (action.kind == ActionKind.TYPE_TEXT && node.isPassword) return ActionResult(false, "Password fields require credential entry")
                        val value = if (action.kind == ActionKind.ENTER_CREDENTIAL) credential else action.text
                        if (value == null) return ActionResult(false, "Credential value is unavailable")
                        val args = android.os.Bundle().apply { putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, value) }
                        val performed = node.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, args)
                        ActionResult(performed, if (performed) "Text entry accepted by Android" else "Android refused text entry")
                    }
                    ActionKind.SCROLL -> {
                        val actionId = when (action.direction) {
                            "up" -> AccessibilityNodeInfo.ACTION_SCROLL_FORWARD
                            "down" -> AccessibilityNodeInfo.ACTION_SCROLL_BACKWARD
                            else -> return ActionResult(false, "Unsupported scroll direction")
                        }
                        val performed = node.performAction(actionId)
                        ActionResult(performed, if (performed) "Scroll accepted by Android" else "Android refused scrolling")
                    }
                    else -> ActionResult(false, "Action is not supported by accessibility")
                }
            } finally {
                if (node !== root) node.recycle()
            }
        } finally {
            root.recycle()
        }
    }

    private fun isLocked(): Boolean {
        val power = getSystemService(Context.POWER_SERVICE) as PowerManager
        val keyguard = getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        return !power.isInteractive || keyguard.isKeyguardLocked
    }

    private fun walk(node: AccessibilityNodeInfo, target: String, path: String, depth: Int, output: MutableList<UiNode>): Boolean {
        if (output.size >= MAX_NODES || depth > MAX_DEPTH) return true
        if (!node.refresh()) return false
        if (node.packageName?.toString() != target) return true
        val password = node.isPassword
        val rect = android.graphics.Rect().also(node::getBoundsInScreen)
        output += UiNode(
            id = path,
            text = if (password) "" else node.text?.toString()?.take(MAX_TEXT).orEmpty(),
            description = if (password) "" else node.contentDescription?.toString()?.take(MAX_TEXT).orEmpty(),
            resourceId = node.viewIdResourceName?.take(MAX_TEXT).orEmpty(),
            className = node.className?.toString()?.take(160).orEmpty(),
            packageName = target,
            editable = node.isEditable,
            password = password,
            clickable = node.isClickable,
            bounds = "${rect.left},${rect.top},${rect.right},${rect.bottom}"
        )
        for (index in 0 until node.childCount) {
            if (output.size >= MAX_NODES) break
            val child = node.getChild(index) ?: continue
            try {
                if (!walk(child, target, "$path/$index", depth + 1, output)) return false
            } finally { child.recycle() }
        }
        return true
    }

    private fun parsePath(id: String): List<Int>? {
        val parts = id.split('/')
        if (parts.size !in 1..MAX_DEPTH + 1 || parts.first() != "0") return null
        val indexes = parts.mapNotNull { it.toIntOrNull() }
        return indexes.takeIf { indexes.size == parts.size && indexes.all { value -> value >= 0 } }
    }

    private fun invalidate() { snapshot = null }

    private data class Snapshot(val target: String, val timestamp: Long)

    companion object {
        private const val MAX_NODES = 300
        private const val MAX_DEPTH = 20
        private const val MAX_TEXT = 500
        private const val MAX_OBSERVATION_AGE_MS = 30_000L
        @Volatile private var connected: AgentAccessibilityService? = null
        @Volatile private var snapshot: Snapshot? = null
        private var lastTimestamp = 0L

        @JvmStatic fun isConnected(): Boolean = connected != null
        @JvmStatic fun isEnabled(context: Context): Boolean {
            val enabled = Settings.Secure.getString(context.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES).orEmpty()
            return enabled.split(':').any {
                val component = ComponentName.unflattenFromString(it)
                component?.let { it.packageName == context.packageName && it.className == name } == true
            }
        }
        @JvmStatic fun openAccessibilitySettings(context: Context) {
            context.startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        }
        private val name: String get() = AgentAccessibilityService::class.java.name
        internal fun currentService(): AgentAccessibilityService? = connected
        @Synchronized private fun nextSnapshotTimestamp(): Long {
            lastTimestamp = maxOf(System.currentTimeMillis(), lastTimestamp + 1)
            return lastTimestamp
        }
    }
}
