package com.mekari.mobile_hardening_kit

import android.annotation.SuppressLint
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

/**
 * Client-side integrity and display observations. Reports only; never blocks a flow.
 * Signals are heuristic and are not a security boundary.
 *
 * Call from the main thread. Lifecycle: [attachActivity] / [detachActivity] follow the
 * host activity; [startObserving] / [stopObserving] follow the event consumer.
 */
class MobileHardeningKit internal constructor(
  context: Context,
  private val files: FileAccess,
  private val monitorEnv: () -> MonitorEnv = MonitorEnv.Companion::system
) : DisplayManager.DisplayListener {
  constructor(context: Context) : this(context, SystemFiles)

  private val context: Context = context.applicationContext
  private val displayManager =
    this.context.getSystemService(Context.DISPLAY_SERVICE) as DisplayManager
  private var activity: Activity? = null
  private var listener: HardeningSignalListener? = null
  private var monitor: IntegrityMonitor? = null
  private var protection = ScreenProtection.OFF
  private var originalSecureFlag: Boolean? = null
  private var recentsOverridden = false
  private var recordingVisible = false
  private var screenshotCallback: Any? = null
  private var recordingCallback: Any? = null
  private var recordingWindowManager: WindowManager? = null

  /** Returns observations in detection order, at most one per type. Unsupported checks are omitted. */
  fun snapshot(config: HardeningConfig = HardeningConfig()): List<HardeningSignal> {
    val signals = mutableListOf<HardeningSignal>()
    fun add(type: String, vararg details: Pair<String, Any>) {
      signals.add(signal(type, details.toMap()))
    }

    rootSignal()?.let(signals::add)
    signals += runtimeSignals()

    val expectedCertificate = config.expectedSigningCertificateSha256
    if (expectedCertificate != null) {
      val installed = signingCertificateSha256s()
      val expected = expectedCertificate.replace(":", "")
      // Every reported signer must match; an extra forged certificate must not pass.
      if (installed.isEmpty() || !installed.all { it.equals(expected, true) }) {
        add(HardeningSignalType.SIGNATURE_MISMATCH, "certificateAvailable" to installed.isNotEmpty())
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
   * Applies [protection] to the attached activity window and reports what was actually applied.
   * Opt-in; [ScreenProtection.OFF] restores the window. Call from the main thread.
   *
   * Android mapping:
   * - Effective FLAG_SECURE = `blockCapture` || the window was already secure before attach ||
   *   (`obscureWhileCaptured` && a screen recording is visible, Android 15+).
   * - `obscureAppSwitcher`: Android 13+ uses `setRecentsScreenshotEnabled(false)`. Below 13 it is reported
   *   applied only when `blockCapture` is on (FLAG_SECURE already hides Recents), else `obscureAppSwitcher:apiLevel`.
   * - `obscureWhileCaptured`: Android 15+ uses the screen-recording callback. Below 15 it is reported applied
   *   only when `blockCapture` is on (FLAG_SECURE covers every recording), else `obscureWhileCaptured:apiLevel`.
   * - No attached activity: requested options are reported as `<option>:noActivity` and re-applied by [attachActivity].
   */
  fun setScreenProtection(protection: ScreenProtection): ScreenProtectionState {
    this.protection = protection
    return applyScreenProtection()
  }

  /** Binds the host activity for window protection and capture callbacks. */
  fun attachActivity(target: Activity) {
    activity = target
    originalSecureFlag =
      (target.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE) != 0
    applyScreenProtection()
    if (listener != null) registerScreenshotCallback(target)
    monitor?.onAttach(target)
  }

  /** Unbinds the activity and restores its original FLAG_SECURE and Recents state. */
  fun detachActivity() {
    monitor?.onDetach()
    unregisterScreenshotCallback()
    unregisterRecordingCallback()
    activity?.let { target ->
      if (recentsOverridden) setRecentsScreenshotEnabled(target, true)
      originalSecureFlag?.let { setSecure(target, it) }
    }
    recentsOverridden = false
    originalSecureFlag = null
    activity = null
  }

  /**
   * Starts delivering external-display changes, screenshot events (Android 14+) and screen-recording
   * state (Android 15+) to [target].
   */
  fun startObserving(target: HardeningSignalListener) {
    listener = target
    displayManager.registerDisplayListener(this, null)
    activity?.let(::registerScreenshotCallback)
    // A fresh registration already emits its initial state; replay only for an existing one.
    val recordingAlreadyRegistered = recordingCallback != null
    syncRecordingCallback()
    if (recordingAlreadyRegistered && recordingVisible) emitRecordingState()
  }

  /**
   * Starts the runtime integrity monitor: re-checks on an interval and on resume and delivers only new,
   * changed or cleared findings to [listener] on the main thread. Replaces a running monitor. Independent of
   * [startObserving]. Call from the main thread.
   */
  fun startMonitoring(
    config: IntegrityMonitorConfig,
    listener: HardeningSignalListener,
    hardeningConfig: HardeningConfig = HardeningConfig()
  ) {
    stopMonitoring()
    monitor = IntegrityMonitor(config, monitorEnv(), listener) { tier ->
      if (tier == IntegrityTier.FULL) snapshot(hardeningConfig) else runtimeSignals()
    }.also { it.start(activity) }
  }

  /** Stops the monitor and drops its state. Safe to call when not monitoring. */
  fun stopMonitoring() {
    monitor?.stop()
    monitor = null
  }

  /** Runs one full monitor pass now (trigger `manual`). No-op when not monitoring. */
  fun checkIntegrityNow() {
    monitor?.checkNow()
  }

  /** Stops event delivery. Safe to call when not observing. */
  fun stopObserving() {
    listener = null
    displayManager.unregisterDisplayListener(this)
    unregisterScreenshotCallback()
    syncRecordingCallback()
  }

  /** The runtime-attach tier (instrumentation, debugger); the monitor runs it alone on its interval. */
  internal fun runtimeSignals(): List<HardeningSignal> = listOfNotNull(instrumentationSignal(), debuggerSignal())

  private fun rootSignal(): HardeningSignal? {
    val artifacts = ROOT_PATHS.filter(files::exists)
    val testKeys = Build.TAGS?.contains("test-keys") == true
    val hasMagiskManager = runCatching {
      context.packageManager.getPackageInfo(MAGISK_PACKAGE, 0)
    }.isSuccess
    val markers = mountMarkers()
    val techniques = listOfNotNull(
      "paths".takeIf { artifacts.isNotEmpty() },
      "buildTags".takeIf { testKeys },
      "managerPackage".takeIf { hasMagiskManager },
      "mountinfo".takeIf { markers.isNotEmpty() }
    )
    if (techniques.isEmpty()) return null
    val details = mutableMapOf<String, Any>()
    if (artifacts.isNotEmpty()) details["artifacts"] = artifacts.take(8)
    if (testKeys) details["testKeys"] = true
    if (hasMagiskManager) details["managerPackage"] = MAGISK_PACKAGE
    if (markers.isNotEmpty()) details["mountMarkers"] = markers
    details["techniques"] = techniques
    return signal(HardeningSignalType.ROOT, details)
  }

  /** Marker keywords found in the root, mount-point, filesystem-type and source fields of `/proc/self/mountinfo`. */
  private fun mountMarkers(): List<String> {
    val rows = runCatching { files.readLines("/proc/self/mountinfo") }.getOrDefault(emptyList()).map { row ->
      val fields = row.trim().lowercase().split(Regex("\\s+"))
      val separator = fields.indexOf("-")
      fields.drop(3).take(2) + if (separator >= 0) fields.drop(separator + 1).take(2) else emptyList()
    }
    return MOUNT_MARKERS.filter { marker -> rows.any { fields -> fields.any { it.contains(marker) } } }.take(8)
  }

  private class Mapping(val perms: String, val path: String)

  private fun readMappings(): List<Mapping> =
    runCatching { files.readLines("/proc/self/maps") }.getOrDefault(emptyList()).mapNotNull { row ->
      val columns = row.trim().split(Regex("\\s+"), limit = 6)
      if (columns.size < 2) null else Mapping(columns[1], columns.getOrElse(5) { "" }.removeSuffix(" (deleted)"))
    }

  private fun threadNames(): List<String> = runCatching {
    files.list("/proc/self/task").mapNotNull { tid ->
      runCatching { files.readLines("/proc/self/task/$tid/comm").firstOrNull()?.trim() }.getOrNull()
    }
  }.getOrDefault(emptyList()).distinct()

  private fun instrumentationSignal(): HardeningSignal? {
    val mappings = readMappings()
    val mapPaths = mappings.map { it.path }.filter { path -> HOOK_TERMS.any(path.lowercase()::contains) }.distinct()
    val memfdPaths = mappings.filter {
      it.perms.endsWith("xp") && it.path.startsWith("/memfd:") && it.path != "/memfd:jit-cache"
    }.map { it.path }.distinct()
    val anonRwx = mappings.count { it.perms == "rwxp" && it.path.isEmpty() }
    val artSegments = mappings.count { it.perms == "r-xp" && it.path.endsWith("/libart.so") }
    val threads = threadNames()
    val threadPrimary = threads.any(FRIDA_THREADS::contains)
    val threadArtifacts = if (threadPrimary) {
      threads.filter { it in FRIDA_THREADS || it in GLIB_THREADS }.map { "thread:$it" }
    } else emptyList()
    val port = if (Build.VERSION.SDK_INT <= 28) listeningFridaPort() else null

    val techniques = listOfNotNull(
      "maps".takeIf { mapPaths.isNotEmpty() },
      "threadName".takeIf { threadPrimary },
      "memfdExec".takeIf { memfdPaths.isNotEmpty() },
      "artSegments".takeIf { artSegments > 1 },
      "port".takeIf { port != null }
    )
    if (techniques.isEmpty()) return null
    return signal(
      HardeningSignalType.INSTRUMENTATION,
      mapOf(
        "artifacts" to (mapPaths + memfdPaths + threadArtifacts).distinct().map { it.take(120) }.take(8),
        "tracerPort" to (port ?: 0),
        "anonRwxCount" to anonRwx,
        "artTextSegments" to artSegments,
        "techniques" to techniques + listOfNotNull("anonRwx".takeIf { anonRwx > 0 })
      )
    )
  }

  private fun debuggerSignal(): HardeningSignal? {
    val connected = Debug.isDebuggerConnected()
    val jdwp = connected || Debug.waitingForDebugger()
    val traced = runCatching {
      files.readLines("/proc/self/status").first { it.startsWith("TracerPid:") }
        .substringAfter(':').trim().toLong() != 0L
    }.getOrDefault(false)
    if (!jdwp && !traced) return null
    return signal(
      HardeningSignalType.DEBUGGER_ATTACH,
      mapOf(
        "debuggerConnected" to connected,
        "tracerPid" to traced,
        "techniques" to listOfNotNull("jdwp".takeIf { jdwp }, "tracerPid".takeIf { traced })
      )
    )
  }

  private fun listeningFridaPort(): Int? = runCatching {
    files.readLines("/proc/net/tcp").drop(1).firstNotNullOfOrNull { row ->
      val columns = row.trim().split(Regex("\\s+"))
      if (columns.size > 3 && columns[1].substringAfter(':', "").toIntOrNull(16) in listOf(27042, 27043) &&
        columns[3] == "0A") columns[1].substringAfter(':').toInt(16) else null
    }
  }.getOrNull()

  @Suppress("DEPRECATION")
  @SuppressLint("PackageManagerGetSignatures") // API < 28 has no alternative; all signers are validated by the caller.
  private fun signingCertificateSha256s(): List<String> = runCatching {
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
    signatures.orEmpty().map { signature ->
      MessageDigest.getInstance("SHA-256").digest(signature.toByteArray())
        .joinToString("") { "%02x".format(it) }
    }
  }.getOrDefault(emptyList())

  private fun signal(type: String, metadata: Map<String, Any>) =
    HardeningSignal(type, isoTimestamp(), metadata)

  private fun applyScreenProtection(): ScreenProtectionState {
    val target = activity
    if (target == null) {
      return ScreenProtectionState(
        captureBlocked = false,
        obscuresWhileCaptured = false,
        obscuresAppSwitcher = false,
        unavailable = listOfNotNull(
          "blockCapture:noActivity".takeIf { protection.blockCapture },
          "obscureWhileCaptured:noActivity".takeIf { protection.obscureWhileCaptured },
          "obscureAppSwitcher:noActivity".takeIf { protection.obscureAppSwitcher }
        )
      )
    }
    syncRecordingCallback()
    applyWindowFlag()

    val recentsApi = Build.VERSION.SDK_INT >= 33
    if (recentsApi && (protection.obscureAppSwitcher || recentsOverridden)) {
      setRecentsScreenshotEnabled(target, !protection.obscureAppSwitcher)
      recentsOverridden = protection.obscureAppSwitcher
    }
    val switcherApplied = protection.obscureAppSwitcher && (recentsApi || protection.blockCapture)
    val whileCapturedApplied =
      protection.obscureWhileCaptured && (Build.VERSION.SDK_INT >= 35 || protection.blockCapture)
    return ScreenProtectionState(
      captureBlocked = protection.blockCapture,
      obscuresWhileCaptured = whileCapturedApplied,
      obscuresAppSwitcher = switcherApplied,
      unavailable = listOfNotNull(
        "obscureWhileCaptured:apiLevel".takeIf { protection.obscureWhileCaptured && !whileCapturedApplied },
        "obscureAppSwitcher:apiLevel".takeIf { protection.obscureAppSwitcher && !switcherApplied }
      )
    )
  }

  private fun applyWindowFlag() {
    val target = activity ?: return
    val whileRecording = protection.obscureWhileCaptured && recordingVisible
    setSecure(target, protection.blockCapture || originalSecureFlag == true || whileRecording)
  }

  private fun setSecure(target: Activity, secure: Boolean) {
    if (secure) target.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    else target.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
  }

  @TargetApi(33)
  private fun setRecentsScreenshotEnabled(target: Activity, enabled: Boolean) =
    target.setRecentsScreenshotEnabled(enabled)

  /** One shared registration serves both observation (listener) and protection (obscureWhileCaptured). */
  private fun syncRecordingCallback() {
    val target = activity
    if (Build.VERSION.SDK_INT >= 35 && target != null && (listener != null || protection.obscureWhileCaptured)) {
      registerRecordingCallback(target)
    } else {
      unregisterRecordingCallback()
    }
  }

  @TargetApi(35)
  private fun registerRecordingCallback(target: Activity) {
    if (recordingCallback != null) return
    val callback = java.util.function.Consumer<Int> { state -> onRecordingState(state) }
    val manager = target.windowManager
    recordingWindowManager = manager
    recordingCallback = callback
    onRecordingState(manager.addScreenRecordingCallback(target.mainExecutor, callback))
  }

  @TargetApi(35)
  @Suppress("UNCHECKED_CAST")
  private fun unregisterRecordingCallback() {
    val callback = recordingCallback as? java.util.function.Consumer<Int> ?: return
    recordingWindowManager?.removeScreenRecordingCallback(callback)
    recordingCallback = null
    recordingWindowManager = null
    recordingVisible = false
    applyWindowFlag()
  }

  @TargetApi(35) // Only reachable through the API 35 callback registration.
  private fun onRecordingState(state: Int) {
    val visible = state == WindowManager.SCREEN_RECORDING_STATE_VISIBLE
    if (visible == recordingVisible) return
    recordingVisible = visible
    applyWindowFlag()
    emitRecordingState()
  }

  private fun emitRecordingState() {
    listener?.onSignal(
      signal(
        HardeningSignalType.SCREEN_CAPTURE_ACTIVE,
        mapOf("active" to recordingVisible, "source" to "screenRecordingCallback")
      )
    )
  }

  private fun registerScreenshotCallback(target: Activity) {
    if (Build.VERSION.SDK_INT < 34 || listener == null || screenshotCallback != null) return
    val callback = Activity.ScreenCaptureCallback {
      listener?.onSignal(signal(HardeningSignalType.SCREENSHOT_TAKEN, mapOf("source" to "systemCallback")))
    }
    target.registerScreenCaptureCallback(target.mainExecutor, callback)
    screenshotCallback = callback
  }

  private fun unregisterScreenshotCallback() {
    if (Build.VERSION.SDK_INT < 34) return // Never registered below API 34.
    val callback = screenshotCallback as? Activity.ScreenCaptureCallback ?: return
    activity?.unregisterScreenCaptureCallback(callback)
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

  private companion object {
    const val MAGISK_PACKAGE = "com.topjohnwu.magisk"
    val ROOT_PATHS = listOf(
      "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", "/system/xbin/su",
      "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su",
      "/system/bin/.ext/.su", "/system/usr/we-need-root/su-backup", "/system/xbin/daemonsu",
      "/data/adb/magisk", "/sbin/.magisk", "/data/adb/ksu", "/data/adb/ap"
    )
    val MOUNT_MARKERS = listOf("magisk", "zygisk", "/adb/modules")
    val HOOK_TERMS = listOf("frida", "frida-gadget", "xposed", "lsposed", "substrate", "libhooker")
    val FRIDA_THREADS = setOf("gum-js-loop", "pool-frida")
    val GLIB_THREADS = setOf("gmain", "gdbus")
  }

  override fun onDisplayAdded(displayId: Int) = emitExternalDisplayState()
  override fun onDisplayRemoved(displayId: Int) = emitExternalDisplayState()
  override fun onDisplayChanged(displayId: Int) = emitExternalDisplayState()
}

/** Filesystem reads used by detectors; replaceable in tests. */
internal interface FileAccess {
  fun exists(path: String): Boolean
  fun readLines(path: String): List<String>
  fun list(path: String): List<String>
}

internal object SystemFiles : FileAccess {
  override fun exists(path: String): Boolean = File(path).exists()
  override fun readLines(path: String): List<String> = File(path).readLines()
  override fun list(path: String): List<String> = File(path).list()?.toList().orEmpty()
}
