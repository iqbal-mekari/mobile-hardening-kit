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
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.io.File
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

class MobileHardeningKitPlugin : FlutterPlugin, MethodChannel.MethodCallHandler,
    EventChannel.StreamHandler, ActivityAware, DisplayManager.DisplayListener {
  private lateinit var context: Context
  private lateinit var methods: MethodChannel
  private lateinit var events: EventChannel
  private var activity: Activity? = null
  private var sink: EventChannel.EventSink? = null
  private var displayManager: DisplayManager? = null
  private var protected = false
  private var originalSecureFlag: Boolean? = null
  private var screenshotCallback: Any? = null

  override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
    context = binding.applicationContext
    methods = MethodChannel(binding.binaryMessenger, "mobile_hardening_kit")
    events = EventChannel(binding.binaryMessenger, "mobile_hardening_kit/events")
    methods.setMethodCallHandler(this)
    events.setStreamHandler(this)
    displayManager = context.getSystemService(Context.DISPLAY_SERVICE) as DisplayManager
  }

  override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
    when (call.method) {
      "snapshot" -> result.success(collectSignals(
        call.argument<String>("expectedSigningCertificateSha256"),
        call.argument<List<*>>("trustedAccessibilityPackages")?.mapNotNull { it as? String }?.toSet().orEmpty()
      ))
      "setScreenProtectionEnabled" -> {
        protected = call.argument<Boolean>("enabled") ?: false
        applyScreenProtection()
        result.success(null)
      }
      else -> result.notImplemented()
    }
  }

  private fun collectSignals(expectedCertificate: String?, trustedAccessibilityPackages: Set<String>): List<Map<String, Any>> {
    val signals = mutableListOf<Map<String, Any>>()
    fun add(type: String, confidence: String, vararg details: Pair<String, Any>) {
      signals.add(mapOf(
        "type" to type,
        "confidence" to confidence,
        "observedAt" to isoTimestamp(),
        "metadata" to details.toMap()
      ))
    }

    val rootArtifacts = listOf(
      "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", "/system/xbin/su",
      "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su",
      "/system/bin/.ext/.su", "/system/usr/we-need-root/su-backup", "/system/xbin/daemonsu",
      "/data/adb/magisk", "/sbin/.magisk", "/data/adb/ksu", "/data/adb/ap"
    ).filter { File(it).exists() }
    val testKeys = Build.TAGS?.contains("test-keys") == true
    if (rootArtifacts.isNotEmpty()) {
      add("root", "high", "artifacts" to rootArtifacts.take(8), "testKeys" to testKeys)
    } else if (testKeys) {
      add("root", "medium", "testKeys" to true)
    }

    val maps = runCatching { File("/proc/self/maps").readLines() }.getOrDefault(emptyList())
    val hookArtifacts = maps.asSequence().filter {
      val line = it.lowercase()
      listOf("frida", "gum-js-loop", "gadget", "xposed", "lsposed", "substrate", "libhooker").any(line::contains)
    }.map { it.substringAfterLast(' ').take(120) }.distinct().take(8).toList()
    val listeningPort = listeningFridaPort()
    if (hookArtifacts.isNotEmpty() || listeningPort != null) {
      add("instrumentation", "high", "artifacts" to hookArtifacts, "tracerPort" to (listeningPort ?: 0))
    }

    if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) {
      add("debuggerAttach", "high", "debuggerConnected" to Debug.isDebuggerConnected())
    }

    if (expectedCertificate != null) {
      val installed = signingCertificateSha256()
      if (installed == null || !installed.equals(expectedCertificate.replace(":", "").lowercase(), true)) {
        add("signatureMismatch", "high", "certificateAvailable" to (installed != null))
      }
    }

    val emulatorIndicators = listOf(
      Build.FINGERPRINT.startsWith("generic"), Build.FINGERPRINT.lowercase().contains("emulator"),
      Build.MODEL.contains("Emulator", true), Build.MODEL.contains("Android SDK built for", true),
      Build.HARDWARE.contains("goldfish", true), Build.HARDWARE.contains("ranchu", true),
      Build.PRODUCT.contains("sdk", true), Build.MANUFACTURER.contains("Genymotion", true)
    ).count { it }
    if (emulatorIndicators >= 2) add("emulator", "medium", "indicatorCount" to emulatorIndicators)

    val enabledServices = Settings.Secure.getString(context.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)
      ?.split(':').orEmpty().filter(String::isNotBlank)
    val externalPackages = enabledServices.map { it.substringBefore('/') }.filter { it != context.packageName }.distinct()
    val unknownPackages = externalPackages.filterNot(trustedAccessibilityPackages::contains)
    if (unknownPackages.isNotEmpty()) {
      add("accessibilityUnrecognized", "low", "serviceCount" to unknownPackages.size)
    }
    val devMode = Settings.Global.getInt(context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
    val adbEnabled = Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
    if (devMode || adbEnabled) add("devModeEnabled", "low", "developerOptions" to devMode, "usbDebugging" to adbEnabled)

    val externalDisplays = presentationDisplayCount()
    if (externalDisplays > 0) add("externalDisplay", "medium", "displayCount" to externalDisplays)
    return signals
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

  override fun onListen(arguments: Any?, eventSink: EventChannel.EventSink) {
    sink = eventSink
    displayManager?.registerDisplayListener(this, null)
    activity?.let(::registerScreenshotCallback)
  }

  override fun onCancel(arguments: Any?) {
    sink = null
    displayManager?.unregisterDisplayListener(this)
    unregisterScreenshotCallback()
  }

  override fun onAttachedToActivity(binding: ActivityPluginBinding) {
    activity = binding.activity
    originalSecureFlag =
      (binding.activity.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE) != 0
    applyScreenProtection()
    if (sink != null) registerScreenshotCallback(binding.activity)
  }

  private fun isoTimestamp(): String = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US)
    .apply { timeZone = TimeZone.getTimeZone("UTC") }.format(Date())

  override fun onDetachedFromActivityForConfigChanges() = detachActivity()
  override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) = onAttachedToActivity(binding)
  override fun onDetachedFromActivity() = detachActivity()

  private fun detachActivity() {
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

  private fun applyScreenProtection() {
    activity?.window?.let { window ->
      if (protected || originalSecureFlag == true) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
      else window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }
  }

  @TargetApi(34)
  private fun registerScreenshotCallback(target: Activity) {
    if (Build.VERSION.SDK_INT < 34 || sink == null || screenshotCallback != null) return
    val callback = Activity.ScreenCaptureCallback {
      sink?.success(signal("screenshotTaken", "high", mapOf("source" to "systemCallback")))
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

  private fun signal(type: String, confidence: String, metadata: Map<String, Any>) = mapOf(
    "type" to type, "confidence" to confidence, "observedAt" to isoTimestamp(), "metadata" to metadata
  )

  private fun presentationDisplayCount(): Int = displayManager
    ?.getDisplays(DisplayManager.DISPLAY_CATEGORY_PRESENTATION)
    ?.count { it.displayId != 0 } ?: 0

  private fun emitExternalDisplayState() {
    val count = presentationDisplayCount()
    sink?.success(signal("externalDisplay", if (count > 0) "medium" else "low", mapOf("connected" to (count > 0), "displayCount" to count)))
  }

  override fun onDisplayAdded(displayId: Int) = emitExternalDisplayState()
  override fun onDisplayRemoved(displayId: Int) = emitExternalDisplayState()
  override fun onDisplayChanged(displayId: Int) = emitExternalDisplayState()

  override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
    detachActivity()
    displayManager?.unregisterDisplayListener(this)
    methods.setMethodCallHandler(null)
    events.setStreamHandler(null)
  }

}
