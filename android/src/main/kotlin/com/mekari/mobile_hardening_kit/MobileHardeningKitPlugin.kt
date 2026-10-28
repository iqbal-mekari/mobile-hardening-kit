package com.mekari.mobile_hardening_kit

import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel

/** Flutter adapter: maps channel calls and activity lifecycle onto [MobileHardeningKit]. */
class MobileHardeningKitPlugin : FlutterPlugin, MethodChannel.MethodCallHandler,
    EventChannel.StreamHandler, ActivityAware {
  private lateinit var kit: MobileHardeningKit
  private lateinit var methods: MethodChannel
  private lateinit var events: EventChannel
  private lateinit var integrityEvents: EventChannel

  /** Integrity-monitor stream; separate from the screen-events handler (the plugin itself). */
  internal val integrityHandler = object : EventChannel.StreamHandler {
    override fun onListen(arguments: Any?, eventSink: EventChannel.EventSink) {
      val args = arguments as? Map<*, *>
      val interval = (args?.get("intervalMs") as? Number)?.toLong() ?: DEFAULT_INTERVAL_MS
      kit.startMonitoring(
        IntegrityMonitorConfig(
          intervalMs = interval,
          checkOnResume = args?.get("checkOnResume") as? Boolean ?: true
        ),
        { eventSink.success(it.toMap()) },
        HardeningConfig(
          args?.get("expectedSigningCertificateSha256") as? String,
          (args?.get("trustedAccessibilityPackages") as? List<*>)
            ?.mapNotNull { it as? String }?.toSet().orEmpty()
        )
      )
    }

    override fun onCancel(arguments: Any?) = kit.stopMonitoring()
  }

  override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
    kit = MobileHardeningKit(binding.applicationContext)
    methods = MethodChannel(binding.binaryMessenger, "mobile_hardening_kit")
    events = EventChannel(binding.binaryMessenger, "mobile_hardening_kit/events")
    integrityEvents = EventChannel(binding.binaryMessenger, "mobile_hardening_kit/integrity_events")
    methods.setMethodCallHandler(this)
    events.setStreamHandler(this)
    integrityEvents.setStreamHandler(integrityHandler)
  }

  override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
    when (call.method) {
      "snapshot" -> result.success(
        kit.snapshot(
          HardeningConfig(
            call.argument<String>("expectedSigningCertificateSha256"),
            call.argument<List<*>>("trustedAccessibilityPackages")
              ?.mapNotNull { it as? String }?.toSet().orEmpty()
          )
        ).map(HardeningSignal::toMap)
      )
      "setScreenProtection" -> result.success(
        kit.setScreenProtection(
          ScreenProtection(
            blockCapture = call.argument<Boolean>("blockCapture") ?: false,
            obscureWhileCaptured = call.argument<Boolean>("obscureWhileCaptured") ?: false,
            obscureAppSwitcher = call.argument<Boolean>("obscureAppSwitcher") ?: false
          )
        ).toMap()
      )
      "checkIntegrityNow" -> {
        kit.checkIntegrityNow()
        result.success(null)
      }
      else -> result.notImplemented()
    }
  }

  override fun onListen(arguments: Any?, eventSink: EventChannel.EventSink) {
    kit.startObserving { eventSink.success(it.toMap()) }
  }

  override fun onCancel(arguments: Any?) = kit.stopObserving()

  override fun onAttachedToActivity(binding: ActivityPluginBinding) = kit.attachActivity(binding.activity)
  override fun onDetachedFromActivityForConfigChanges() = kit.detachActivity()
  override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) =
    kit.attachActivity(binding.activity)
  override fun onDetachedFromActivity() = kit.detachActivity()

  override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
    kit.detachActivity()
    kit.stopObserving()
    kit.stopMonitoring()
    methods.setMethodCallHandler(null)
    events.setStreamHandler(null)
    integrityEvents.setStreamHandler(null)
  }

  private companion object {
    const val DEFAULT_INTERVAL_MS = 30_000L
  }
}
