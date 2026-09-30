package com.mekari.mobile_hardening_kit

import android.annotation.TargetApi
import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.display.DisplayManager
import android.os.Build
import android.os.Debug
import android.provider.Settings
import android.view.WindowManager
import java.io.File
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * Client-side integrity and display observations. Reports only; never blocks a flow.
 * Signals are heuristic and are not a security boundary.
 *
 * Call from the main thread. Lifecycle: [attachActivity] / [detachActivity] follow the
 * host activity; [startObserving] / [stopObserving] follow the event consumer.
 */
class MobileHardeningKit(context: Context) : DisplayManager.DisplayListener {
  private val context: Context = context.applicationContext
  private val displayManager =
    this.context.getSystemService(Context.DISPLAY_SERVICE) as DisplayManager
  private var activity: Activity? = null
  private var listener: HardeningSignalListener? = null
  private var screenProtectionEnabled = false
  private var originalSecureFlag: Boolean? = null
  private var screenshotCallback: Any? = null

  /** Returns observations in detection order, at most one per type. Unsupported checks are omitted. */
  fun snapshot(config: HardeningConfig = HardeningConfig()): List<HardeningSignal> {
    val signals = mutableListOf<HardeningSignal>()
    fun add(type: String, vararg details: Pair<String, Any>) {
      signals.add(signal(type, details.toMap()))
    }

    val rootArtifacts = listOf(
      "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", "/system/xbin/su",
      "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su",
      "/system/bin/.ext/.su", "/system/usr/we-need-root/su-backup", "/system/xbin/daemonsu",
      "/data/adb/magisk", "/sbin/.magisk", "/data/adb/ksu", "/data/adb/ap"
    ).filter { File(it).exists() }
    val testKeys = Build.TAGS?.contains("test-keys") == true
    val magiskManagerPackage = "com.topjohnwu.magisk"
    val hasMagiskManager = runCatching {
      context.packageManager.getPackageInfo(magiskManagerPackage, 0)
    }.isSuccess
    val rootDetails = mutableListOf<Pair<String, Any>>()
    if (rootArtifacts.isNotEmpty()) rootDetails += "artifacts" to rootArtifacts.take(8)
    if (testKeys) rootDetails += "testKeys" to true
    if (hasMagiskManager) rootDetails += "managerPackage" to magiskManagerPackage
    if (rootDetails.isNotEmpty()) add(HardeningSignalType.ROOT, *rootDetails.toTypedArray())

    val maps = runCatching { File("/proc/self/maps").readLines() }.getOrDefault(emptyList())
    val hookArtifacts = maps.asSequence().filter {
      val line = it.lowercase()
      listOf("frida", "gum-js-loop", "gadget", "xposed", "lsposed", "substrate", "libhooker").any(line::contains)
    }.mapNotNull { row ->
      row.trim().split(Regex("\\s+"), limit = 6).getOrNull(5)
        ?.removeSuffix(" (deleted)")?.take(120)
    }.distinct().take(8).toList()
    val listeningPort = listeningFridaPort()
    if (hookArtifacts.isNotEmpty() || listeningPort != null) {
      add(HardeningSignalType.INSTRUMENTATION, "artifacts" to hookArtifacts, "tracerPort" to (listeningPort ?: 0))
    }

    if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) {
      add(HardeningSignalType.DEBUGGER_ATTACH, "debuggerConnected" to Debug.isDebuggerConnected())
    }

    val expectedCertificate = config.expectedSigningCertificateSha256
    if (expectedCertificate != null) {
      val installed = signingCertificateSha256()
      if (installed == null || !installed.equals(expectedCertificate.replace(":", "").lowercase(), true)) {
        add(HardeningSignalType.SIGNATURE_MISMATCH, "certificateAvailable" to (installed != null))
      }
    }

    val emulatorIndicators = listOf(
      Build.FINGERPRINT.startsWith("generic"), Build.FINGERPRINT.lowercase().contains("emulator"),
      Build.MODEL.contains("Emulator", true), Build.MODEL.contains("Android SDK built for", true),
      Build.HARDWARE.contains("goldfish", true), Build.HARDWARE.contains("ranchu", true),
      Build.PRODUCT.contains("sdk", true), Build.MANUFACTURER.contains("Genymotion", true)
    ).count { it }
    if (emulatorIndicators >= 2) add(HardeningSignalType.EMULATOR, "indicatorCount" to emulatorIndicators)

    val enabledServices = Settings.Secure.getString(context.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)
      ?.split(':').orEmpty().filter(String::isNotBlank)
    val externalPackages = enabledServices.map { it.substringBefore('/') }.filter { it != context.packageName }.distinct()
    val unknownPackages = externalPackages.filterNot(config.trustedAccessibilityPackages::contains)
    if (unknownPackages.isNotEmpty()) {
      add(HardeningSignalType.ACCESSIBILITY_UNRECOGNIZED, "serviceCount" to unknownPackages.size)
    }
    val devMode = Settings.Global.getInt(context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
    val adbEnabled = Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
    if (devMode || adbEnabled) add(HardeningSignalType.DEV_MODE_ENABLED, "developerOptions" to devMode, "usbDebugging" to adbEnabled)

    val externalDisplays = presentationDisplayCount()
    if (externalDisplays > 0) add(HardeningSignalType.EXTERNAL_DISPLAY, "displayCount" to externalDisplays)
    return signals
  }

  /**
   * Enables or disables FLAG_SECURE on the attached activity window. Opt-in, disabled by default.
   * A window that was already secure before attach stays secure.
   */
  fun setScreenProtectionEnabled(enabled: Boolean) {
    screenProtectionEnabled = enabled
    applyScreenProtection()
  }

  /** Binds the host activity for window protection and screenshot callbacks. */
  fun attachActivity(target: Activity) {
    activity = target
    originalSecureFlag =
      (target.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE) != 0
    applyScreenProtection()
    if (listener != null) registerScreenshotCallback(target)
  }

  /** Unbinds the activity and restores its original FLAG_SECURE state. */
  fun detachActivity() {
    unregisterScreenshotCallback()
    originalSecureFlag?.let { wasSecure ->
      activity?.window?.let { window ->
        if (wasSecure) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        else window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
      }
    }
    originalSecureFlag = null
    activity = null
  }

  /** Starts delivering external-display changes and (Android 14+) screenshot events to [target]. */
  fun startObserving(target: HardeningSignalListener) {
    listener = target
    displayManager.registerDisplayListener(this, null)
    activity?.let(::registerScreenshotCallback)
  }

  /** Stops event delivery. Safe to call when not observing. */
  fun stopObserving() {
    listener = null
    displayManager.unregisterDisplayListener(this)
    unregisterScreenshotCallback()
  }

  private fun listeningFridaPort(): Int? = runCatching {
    File("/proc/net/tcp").readLines().drop(1).firstNotNullOfOrNull { row ->
      val columns = row.trim().split(Regex("\\s+"))
      if (columns.size > 3 && columns[1].substringAfter(':', "").toIntOrNull(16) in listOf(27042, 27043) &&
        columns[3] == "0A") columns[1].substringAfter(':').toInt(16) else null
    }
  }.getOrNull()

  @Suppress("DEPRECATION")
  private fun signingCertificateSha256(): String? = runCatching {
    val packageInfo = if (Build.VERSION.SDK_INT >= 28) {
      context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
    } else {
      context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES)
    }
    val signatures = if (Build.VERSION.SDK_INT >= 28) {
      packageInfo.signingInfo?.apkContentsSigners
    } else {
      packageInfo.signatures
    }
    signatures?.firstOrNull()?.toByteArray()?.let { bytes ->
      MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    }
  }.getOrNull()

  private fun isoTimestamp(): String = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US)
    .apply { timeZone = TimeZone.getTimeZone("UTC") }.format(Date())

  private fun signal(type: String, metadata: Map<String, Any>) =
    HardeningSignal(type, isoTimestamp(), metadata)

  private fun applyScreenProtection() {
    activity?.window?.let { window ->
      if (screenProtectionEnabled || originalSecureFlag == true) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
      else window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }
  }

  @TargetApi(34)
  private fun registerScreenshotCallback(target: Activity) {
    if (Build.VERSION.SDK_INT < 34 || listener == null || screenshotCallback != null) return
    val callback = Activity.ScreenCaptureCallback {
      listener?.onSignal(signal(HardeningSignalType.SCREENSHOT_TAKEN, mapOf("source" to "systemCallback")))
    }
    target.registerScreenCaptureCallback(target.mainExecutor, callback)
    screenshotCallback = callback
  }

  @TargetApi(34)
  private fun unregisterScreenshotCallback() {
    val callback = screenshotCallback as? Activity.ScreenCaptureCallback ?: return
    if (Build.VERSION.SDK_INT >= 34) activity?.unregisterScreenCaptureCallback(callback)
    screenshotCallback = null
  }

  private fun presentationDisplayCount(): Int = displayManager
    .getDisplays(DisplayManager.DISPLAY_CATEGORY_PRESENTATION)
    .count { it.displayId != 0 }

  private fun emitExternalDisplayState() {
    val count = presentationDisplayCount()
    listener?.onSignal(
      signal(HardeningSignalType.EXTERNAL_DISPLAY, mapOf("connected" to (count > 0), "displayCount" to count))
    )
  }

  override fun onDisplayAdded(displayId: Int) = emitExternalDisplayState()
  override fun onDisplayRemoved(displayId: Int) = emitExternalDisplayState()
  override fun onDisplayChanged(displayId: Int) = emitExternalDisplayState()
}
