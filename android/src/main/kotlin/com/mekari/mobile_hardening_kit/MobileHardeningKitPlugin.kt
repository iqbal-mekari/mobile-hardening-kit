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

  override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
    kit = MobileHardeningKit(binding.applicationContext)
    methods = MethodChannel(binding.binaryMessenger, "mobile_hardening_kit")
    events = EventChannel(binding.binaryMessenger, "mobile_hardening_kit/events")
    methods.setMethodCallHandler(this)
    events.setStreamHandler(this)
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
      "setScreenProtectionEnabled" -> {
        kit.setScreenProtectionEnabled(call.argument<Boolean>("enabled") ?: false)
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
    methods.setMethodCallHandler(null)
    events.setStreamHandler(null)
  }
}
