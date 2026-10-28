package com.mekari.mobile_hardening_kit

/**
 * Opt-in window protection requested through [MobileHardeningKit.setScreenProtection].
 * Every option is independent and off by default.
 */
data class ScreenProtection(
  /** Blank screenshots, recordings, casting and Recents (Android: FLAG_SECURE on the attached window). */
  val blockCapture: Boolean = false,
  /** Obscure the window only while the system reports a screen recording (Android 15+). */
  val obscureWhileCaptured: Boolean = false,
  /** Hide the window content in the app switcher / Recents. */
  val obscureAppSwitcher: Boolean = false
) {
  companion object {
    /** Every option disabled. */
    val OFF = ScreenProtection()
  }
}

/**
 * What the platform actually applied for a [ScreenProtection] request.
 * [unavailable] holds `<option>:<reason>` entries for requested options that could not be applied:
 * `obscureWhileCaptured:apiLevel`, `obscureAppSwitcher:apiLevel`, and `<option>:noActivity`.
 */
data class ScreenProtectionState(
  val captureBlocked: Boolean,
  val obscuresWhileCaptured: Boolean,
  val obscuresAppSwitcher: Boolean,
  val unavailable: List<String> = emptyList()
) {
  /** The channel schema shared with the Flutter plugin. */
  fun toMap(): Map<String, Any> = mapOf(
    "captureBlocked" to captureBlocked,
    "obscuresWhileCaptured" to obscuresWhileCaptured,
    "obscuresAppSwitcher" to obscuresAppSwitcher,
    "unavailable" to unavailable
  )
}
