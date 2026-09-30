package com.mekari.mobile_hardening_kit

/** Signal type identifiers. Values match the Dart `HardeningSignalType` names and the iOS core. */
object HardeningSignalType {
  const val ROOT = "root"
  const val JAILBREAK = "jailbreak"
  const val INSTRUMENTATION = "instrumentation"
  const val DEBUGGER_ATTACH = "debuggerAttach"
  const val SIGNATURE_MISMATCH = "signatureMismatch"
  const val EMULATOR = "emulator"
  const val ACCESSIBILITY_UNRECOGNIZED = "accessibilityUnrecognized"
  const val DEV_MODE_ENABLED = "devModeEnabled"
  const val SCREEN_CAPTURE_ACTIVE = "screenCaptureActive"
  const val SCREENSHOT_TAKEN = "screenshotTaken"
  const val EXTERNAL_DISPLAY = "externalDisplay"
}

/**
 * A point-in-time, heuristic observation. [observedAt] is a UTC ISO-8601 timestamp.
 * [metadata] is bounded and contains no user identifiers.
 */
data class HardeningSignal(
  val type: String,
  val observedAt: String,
  val metadata: Map<String, Any> = emptyMap()
) {
  /** The `type` / `observedAt` / `metadata` map schema shared with the Flutter channel. */
  fun toMap(): Map<String, Any> = mapOf(
    "type" to type,
    "observedAt" to observedAt,
    "metadata" to metadata
  )
}

/** Inputs for [MobileHardeningKit.snapshot]. */
data class HardeningConfig(
  /** Expected signing-certificate SHA-256, hex with or without colons. Null omits the check. */
  val expectedSigningCertificateSha256: String? = null,
  /** Package IDs of accessibility services considered known-good. */
  val trustedAccessibilityPackages: Set<String> = emptySet()
)

/** Receives display/capture state changes while [MobileHardeningKit.startObserving] is active. */
fun interface HardeningSignalListener {
  fun onSignal(signal: HardeningSignal)
}
