package com.mekari.mobile_hardening_kit

import android.app.Activity
import android.os.Build
import android.os.Looper
import android.provider.Settings
import android.view.WindowManager
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.Mockito.mock
import org.mockito.Mockito.verify
import org.mockito.Mockito.`when`
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowDisplayManager
import org.robolectric.util.ReflectionHelpers

private class RecordingResult : MethodChannel.Result {
  var success: Any? = null
  var succeeded = false
  var notImplemented = false
  var errorCode: String? = null
  var errorThread: Thread? = null
  var successThread: Thread? = null

  override fun success(result: Any?) {
    succeeded = true
    success = result
    successThread = Thread.currentThread()
  }

  override fun error(errorCode: String, errorMessage: String?, errorDetails: Any?) {
    this.errorCode = errorCode
    errorThread = Thread.currentThread()
  }

  override fun notImplemented() {
    notImplemented = true
  }
}

private class RecordingSink : EventChannel.EventSink {
  val events = mutableListOf<Any?>()

  override fun success(event: Any?) {
    events += event
  }

  override fun error(errorCode: String, errorMessage: String?, errorDetails: Any?) =
    throw AssertionError("unexpected error $errorCode")

  override fun endOfStream() = Unit
}

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class MobileHardeningKitPluginTest {
  private val context = RuntimeEnvironment.getApplication()
  private val messenger = mock(BinaryMessenger::class.java)
  private val plugin = MobileHardeningKitPlugin()
  private var originalTags: Any? = null

  @Before
  fun setUp() {
    originalTags = ReflectionHelpers.getStaticField<Any?>(Build::class.java, "TAGS")
    ReflectionHelpers.setStaticField(Build::class.java, "TAGS", "release-keys")
    val binding = mock(FlutterPlugin.FlutterPluginBinding::class.java)
    `when`(binding.applicationContext).thenReturn(context)
    `when`(binding.binaryMessenger).thenReturn(messenger)
    plugin.onAttachedToEngine(binding)
  }

  @After
  fun tearDown() {
    ReflectionHelpers.setStaticField(Build::class.java, "TAGS", originalTags)
  }

  private fun call(method: String, arguments: Any? = null): RecordingResult =
    RecordingResult().also { plugin.onMethodCall(MethodCall(method, arguments), it) }

  /** `snapshot` runs on the plugin's worker and completes on the main looper; wait for it. */
  private fun callAsync(method: String, arguments: Any? = null): RecordingResult {
    val result = call(method, arguments)
    val deadline = System.nanoTime() + 10_000_000_000L
    while (!result.succeeded && result.errorCode == null && System.nanoTime() < deadline) {
      shadowOf(Looper.getMainLooper()).idle()
      Thread.sleep(5)
    }
    assertEquals("unexpected error ${result.errorCode}", null, result.errorCode)
    assertTrue("call did not complete", result.succeeded)
    return result
  }

  private fun attach(activity: Activity) {
    val binding = mock(ActivityPluginBinding::class.java)
    `when`(binding.activity).thenReturn(activity)
    plugin.onAttachedToActivity(binding)
  }

  private fun isSecure(activity: Activity) =
    (activity.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE) != 0

  @Test
  fun snapshotWithoutArgumentsReturnsSchemaMaps() {
    ReflectionHelpers.setStaticField(Build::class.java, "TAGS", "test-keys")
    val result = callAsync("snapshot")
    val signal = (result.success as List<*>).single() as Map<*, *>
    assertEquals("root", signal["type"])
    assertTrue(signal["observedAt"] is String)
    assertEquals(mapOf("testKeys" to true, "techniques" to listOf("buildTags")), signal["metadata"])
  }

  @Test
  fun snapshotDecodesTrustedPackagesIgnoringNonStrings() {
    Settings.Secure.putString(
      context.contentResolver,
      Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES,
      "com.trusted/.S:com.other/.S"
    )
    val result = callAsync(
      "snapshot",
      mapOf("trustedAccessibilityPackages" to listOf("com.trusted", 5, null))
    )
    val signal = (result.success as List<*>).single() as Map<*, *>
    assertEquals("accessibilityUnrecognized", signal["type"])
    assertEquals(mapOf("serviceCount" to 1), signal["metadata"])
  }

  @Test
  fun snapshotForwardsExpectedCertificate() {
    val result = callAsync(
      "snapshot",
      mapOf("expectedSigningCertificateSha256" to "ab".repeat(32))
    )
    val signal = (result.success as List<*>).single() as Map<*, *>
    assertEquals("signatureMismatch", signal["type"])
  }

  @Test
  fun snapshotRunsOnABackgroundThreadAndCompletesOnTheMainThread() {
    val result = call("snapshot")
    assertFalse("the platform thread is not blocked by the scan", result.succeeded)
    val result2 = callAsync("snapshot")
    assertEquals(Looper.getMainLooper().thread, result2.successThread)
  }

  @Test
  fun snapshotFailuresAreReportedAsErrorsOnTheMainThread() {
    val failing = mock(MobileHardeningKit::class.java)
    `when`(failing.snapshot(HardeningConfig())).thenThrow(IllegalStateException("boom"))
    ReflectionHelpers.setField(plugin, "kit", failing)
    val result = call("snapshot")
    val deadline = System.nanoTime() + 10_000_000_000L
    while (result.errorCode == null && System.nanoTime() < deadline) {
      shadowOf(Looper.getMainLooper()).idle()
      Thread.sleep(5)
    }
    assertEquals("snapshot_failed", result.errorCode)
    assertEquals(Looper.getMainLooper().thread, result.errorThread)
  }

  @Test
  fun snapshotAfterEngineDetachIsRejectedCleanly() {
    plugin.onDetachedFromEngine(mock(FlutterPlugin.FlutterPluginBinding::class.java))
    assertEquals("unavailable", call("snapshot").errorCode)
    plugin.onDetachedFromEngine(mock(FlutterPlugin.FlutterPluginBinding::class.java))
    assertEquals("unavailable", call("snapshot").errorCode)
  }

  @Test
  fun snapshotAfterTheWorkerIsShutDownIsRejectedCleanly() {
    val worker = ReflectionHelpers.getField<java.util.concurrent.ExecutorService>(plugin, "worker")
    worker.shutdown()
    assertEquals("unavailable", call("snapshot").errorCode)
  }

  @Test
  fun screenProtectionMapsArgumentsAndReturnsTheState() {
    val activity = Robolectric.buildActivity(Activity::class.java).setup().get()
    attach(activity)

    val result = call(
      "setScreenProtection",
      mapOf("blockCapture" to true, "obscureWhileCaptured" to true, "obscureAppSwitcher" to true)
    )
    assertEquals(
      mapOf(
        "captureBlocked" to true, "obscuresWhileCaptured" to true,
        "obscuresAppSwitcher" to true, "unavailable" to emptyList<String>()
      ),
      result.success
    )
    assertTrue(isSecure(activity))

    val partial = call("setScreenProtection", mapOf("obscureAppSwitcher" to true))
    assertEquals(
      mapOf(
        "captureBlocked" to false, "obscuresWhileCaptured" to false,
        "obscuresAppSwitcher" to true, "unavailable" to emptyList<String>()
      ),
      partial.success
    )
    assertFalse(isSecure(activity))

    call("setScreenProtection", mapOf("blockCapture" to true))
    val missing = call("setScreenProtection", null)
    assertEquals(false, (missing.success as Map<*, *>)["captureBlocked"])
    assertFalse("missing arguments disable protection", isSecure(activity))
  }

  @Test
  fun screenProtectionWithoutActivityReportsNoActivity() {
    val result = call("setScreenProtection", mapOf("blockCapture" to true))
    assertEquals(listOf("blockCapture:noActivity"), (result.success as Map<*, *>)["unavailable"])
  }

  @Test
  fun theOldMethodNameIsNotImplemented() {
    assertTrue(call("setScreenProtectionEnabled", mapOf("enabled" to true)).notImplemented)
  }

  @Test
  fun unknownMethodsAreNotImplemented() {
    assertTrue(call("nope").notImplemented)
  }

  @Test
  fun eventStreamDeliversDisplayChangesUntilCancelled() {
    val sink = RecordingSink()
    plugin.onListen(null, sink)
    ShadowDisplayManager.addDisplay("w800dp-h480dp")
    shadowOf(Looper.getMainLooper()).idle()
    val event = sink.events.first() as Map<*, *>
    assertEquals("externalDisplay", event["type"])

    plugin.onCancel(null)
    val count = sink.events.size
    ShadowDisplayManager.addDisplay("w800dp-h480dp")
    shadowOf(Looper.getMainLooper()).idle()
    assertEquals(count, sink.events.size)
  }

  @Test
  fun activityLifecycleRestoresWindowFlagsAndReattaches() {
    val activity = Robolectric.buildActivity(Activity::class.java).setup().get()
    val binding = mock(ActivityPluginBinding::class.java)
    `when`(binding.activity).thenReturn(activity)
    plugin.onAttachedToActivity(binding)
    call("setScreenProtection", mapOf("blockCapture" to true))
    assertTrue(isSecure(activity))

    plugin.onDetachedFromActivityForConfigChanges()
    assertFalse("detach restores the original window state", isSecure(activity))

    plugin.onReattachedToActivityForConfigChanges(binding)
    assertTrue("protection preference survives a config change", isSecure(activity))

    plugin.onDetachedFromActivity()
    assertFalse(isSecure(activity))
  }

  @Test
  fun detachingFromEngineClearsChannelHandlers() {
    val binding = mock(FlutterPlugin.FlutterPluginBinding::class.java)
    plugin.onDetachedFromEngine(binding)
    verify(messenger).setMessageHandler("mobile_hardening_kit", null)
    verify(messenger).setMessageHandler("mobile_hardening_kit/events", null)
    verify(messenger).setMessageHandler("mobile_hardening_kit/integrity_events", null)
  }

  /** Monitor passes run on a background executor and post to the main looper; wait for them. */
  private fun awaitEvents(sink: RecordingSink, count: Int) {
    val deadline = System.nanoTime() + 10_000_000_000L
    while (sink.events.size < count && System.nanoTime() < deadline) {
      shadowOf(Looper.getMainLooper()).idle()
      Thread.sleep(10)
    }
    assertTrue("expected $count events, got ${sink.events.size}", sink.events.size >= count)
  }

  private fun types(sink: RecordingSink) = sink.events.map { (it as Map<*, *>)["type"] }

  @Test
  fun integrityStreamDeliversTheStartPassWithChangeAndTrigger() {
    ReflectionHelpers.setStaticField(Build::class.java, "TAGS", "test-keys")
    val sink = RecordingSink()
    plugin.integrityHandler.onListen(
      mapOf("intervalMs" to 60_000, "checkOnResume" to false), sink
    )
    awaitEvents(sink, 1)
    val event = sink.events.single() as Map<*, *>
    assertEquals("root", event["type"])
    val metadata = event["metadata"] as Map<*, *>
    assertEquals("detected", metadata["change"])
    assertEquals("start", metadata["trigger"])
    plugin.integrityHandler.onCancel(null)
  }

  @Test
  fun integrityStreamAppliesCertificateAndTrustedPackagesFromTheListenArguments() {
    Settings.Secure.putString(
      context.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES,
      "com.trusted/.S:com.other/.S"
    )
    val sink = RecordingSink()
    plugin.integrityHandler.onListen(
      mapOf(
        "expectedSigningCertificateSha256" to "ab".repeat(32),
        "trustedAccessibilityPackages" to listOf("com.trusted", 5, null)
      ),
      sink
    )
    awaitEvents(sink, 2)
    assertEquals(listOf("accessibilityUnrecognized", "signatureMismatch"), types(sink).sortedBy { it.toString() })
    plugin.integrityHandler.onCancel(null)
  }

  @Test
  fun integrityStreamFallsBackToDefaultsForMissingOrInvalidArguments() {
    ReflectionHelpers.setStaticField(Build::class.java, "TAGS", "test-keys")
    for (arguments in listOf(
      null, "bad", mapOf("intervalMs" to "soon", "checkOnResume" to "yes",
        "expectedSigningCertificateSha256" to 7, "trustedAccessibilityPackages" to "x")
    )) {
      val sink = RecordingSink()
      plugin.integrityHandler.onListen(arguments, sink)
      awaitEvents(sink, 1)
      assertEquals(listOf("root"), types(sink))
      plugin.integrityHandler.onCancel(null)
    }
  }

  @Test
  fun checkIntegrityNowReturnsNullAndRunsAManualPassOnlyWhileMonitoring() {
    ReflectionHelpers.setStaticField(Build::class.java, "TAGS", "test-keys")
    val idle = call("checkIntegrityNow")
    assertTrue(idle.succeeded)
    assertEquals(null, idle.success)

    val sink = RecordingSink()
    plugin.integrityHandler.onListen(null, sink)
    awaitEvents(sink, 1)
    ReflectionHelpers.setStaticField(Build::class.java, "TAGS", "release-keys")
    val manual = call("checkIntegrityNow")
    assertTrue(manual.succeeded)
    awaitEvents(sink, 2)
    val cleared = (sink.events[1] as Map<*, *>)["metadata"] as Map<*, *>
    assertEquals("cleared", cleared["change"])
    assertEquals("manual", cleared["trigger"])
    plugin.integrityHandler.onCancel(null)
  }

  @Test
  fun cancelStopsIntegrityDelivery() {
    ReflectionHelpers.setStaticField(Build::class.java, "TAGS", "test-keys")
    val sink = RecordingSink()
    plugin.integrityHandler.onListen(null, sink)
    awaitEvents(sink, 1)
    plugin.integrityHandler.onCancel(null)
    ReflectionHelpers.setStaticField(Build::class.java, "TAGS", "release-keys")
    call("checkIntegrityNow")
    Thread.sleep(200)
    shadowOf(Looper.getMainLooper()).idle()
    assertEquals(1, sink.events.size)
  }

  @Test
  fun engineDetachStopsMonitoring() {
    ReflectionHelpers.setStaticField(Build::class.java, "TAGS", "test-keys")
    val sink = RecordingSink()
    plugin.integrityHandler.onListen(null, sink)
    awaitEvents(sink, 1)
    plugin.onDetachedFromEngine(mock(FlutterPlugin.FlutterPluginBinding::class.java))
    Thread.sleep(200)
    shadowOf(Looper.getMainLooper()).idle()
    assertEquals(1, sink.events.size)
  }
}
