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

  override fun success(result: Any?) {
    succeeded = true
    success = result
  }

  override fun error(errorCode: String, errorMessage: String?, errorDetails: Any?) =
    throw AssertionError("unexpected error $errorCode")

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
    val result = call("snapshot")
    val signal = (result.success as List<*>).single() as Map<*, *>
    assertEquals("root", signal["type"])
    assertTrue(signal["observedAt"] is String)
    assertEquals(mapOf("testKeys" to true), signal["metadata"])
  }

  @Test
  fun snapshotDecodesTrustedPackagesIgnoringNonStrings() {
    Settings.Secure.putString(
      context.contentResolver,
      Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES,
      "com.trusted/.S:com.other/.S"
    )
    val result = call(
      "snapshot",
      mapOf("trustedAccessibilityPackages" to listOf("com.trusted", 5, null))
    )
    val signal = (result.success as List<*>).single() as Map<*, *>
    assertEquals("accessibilityUnrecognized", signal["type"])
    assertEquals(mapOf("serviceCount" to 1), signal["metadata"])
  }

  @Test
  fun snapshotForwardsExpectedCertificate() {
    val result = call(
      "snapshot",
      mapOf("expectedSigningCertificateSha256" to "ab".repeat(32))
    )
    val signal = (result.success as List<*>).single() as Map<*, *>
    assertEquals("signatureMismatch", signal["type"])
  }

  @Test
  fun screenProtectionFollowsTheEnabledArgument() {
    val activity = Robolectric.buildActivity(Activity::class.java).setup().get()
    attach(activity)

    assertTrue(call("setScreenProtectionEnabled", mapOf("enabled" to true)).succeeded)
    assertTrue(isSecure(activity))
    assertTrue(call("setScreenProtectionEnabled", mapOf("enabled" to false)).succeeded)
    assertFalse(isSecure(activity))
    call("setScreenProtectionEnabled", mapOf("enabled" to true))
    call("setScreenProtectionEnabled", null)
    assertFalse("missing argument disables protection", isSecure(activity))
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
    call("setScreenProtectionEnabled", mapOf("enabled" to true))
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
  }
}
