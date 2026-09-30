package com.mekari.mobile_hardening_kit

import android.app.Activity
import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.Signature
import android.hardware.display.DisplayManager
import android.os.Build
import android.provider.Settings
import android.view.WindowManager
import java.security.MessageDigest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.annotation.Implementation
import org.robolectric.annotation.Implements
import org.robolectric.annotation.RealObject
import org.robolectric.shadow.api.Shadow
import org.robolectric.shadows.ShadowDisplayManager
import org.robolectric.util.ReflectionHelpers

/** Robolectric does not model presentation categories; treat every display as a presentation candidate. */
@Implements(DisplayManager::class)
class PresentationDisplayManagerShadow : ShadowDisplayManager() {
  @RealObject
  private lateinit var manager: DisplayManager

  @Implementation
  @Suppress("UNUSED_PARAMETER", "DEPRECATION")
  fun getDisplays(category: String?): Array<android.view.Display> =
    Shadow.directlyOn(manager, DisplayManager::class.java).getDisplays(null)
}

private class FakeFiles(
  private val existing: Set<String> = emptySet(),
  private val contents: Map<String, List<String>> = emptyMap()
) : FileAccess {
  override fun exists(path: String) = path in existing
  override fun readLines(path: String): List<String> =
    contents[path] ?: throw java.io.FileNotFoundException(path)
}

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class MobileHardeningKitTest {
  private lateinit var context: Context
  private val originals = mutableMapOf<String, Any?>()

  @Before
  fun setUp() {
    context = RuntimeEnvironment.getApplication()
    // Start from a clean, non-rooted, non-emulator device profile.
    setBuild("TAGS", "release-keys")
    setBuild("FINGERPRINT", "google/pixel/pixel:14/AP1A/1:user/release-keys")
    setBuild("MODEL", "Pixel 8")
    setBuild("HARDWARE", "tensor")
    setBuild("PRODUCT", "shiba")
    setBuild("MANUFACTURER", "Google")
  }

  @After
  fun tearDown() {
    originals.forEach { (name, value) -> ReflectionHelpers.setStaticField(Build::class.java, name, value) }
  }

  private fun setBuild(name: String, value: String) {
    if (name !in originals) originals[name] = ReflectionHelpers.getStaticField<Any?>(Build::class.java, name)
    ReflectionHelpers.setStaticField(Build::class.java, name, value)
  }

  private fun kit(files: FileAccess = FakeFiles()) = MobileHardeningKit(context, files)

  private fun types(signals: List<HardeningSignal>) = signals.map { it.type }

  @Test
  fun cleanDeviceReportsNothing() {
    assertEquals(emptyList<HardeningSignal>(), kit().snapshot())
  }

  @Test
  fun publicConstructorUsesTheRealFilesystem() {
    // No su binaries or Frida mappings exist on the JVM host.
    assertTrue(HardeningSignalType.ROOT !in types(MobileHardeningKit(context).snapshot()))
  }

  @Test
  fun signalsCarryUtcTimestampAndMapSchema() {
    setBuild("TAGS", "test-keys")
    val signal = kit().snapshot().single()
    assertTrue(signal.observedAt.matches(Regex("""\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z""")))
    assertEquals(
      mapOf("type" to "root", "observedAt" to signal.observedAt, "metadata" to signal.metadata),
      signal.toMap()
    )
  }

  @Test
  fun rootFromArtifactsTestKeysAndMagiskManager() {
    setBuild("TAGS", "dev-keys,test-keys")
    shadowOf(context.packageManager).installPackage(PackageInfo().apply { packageName = "com.topjohnwu.magisk" })
    val files = FakeFiles(existing = setOf("/sbin/su", "/data/adb/magisk"))
    val root = kit(files).snapshot().single { it.type == HardeningSignalType.ROOT }
    assertEquals(listOf("/sbin/su", "/data/adb/magisk"), root.metadata["artifacts"])
    assertEquals(true, root.metadata["testKeys"])
    assertEquals("com.topjohnwu.magisk", root.metadata["managerPackage"])
  }

  @Test
  fun rootArtifactsAreBounded() {
    val many = FakeFiles(
      existing = setOf(
        "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", "/system/xbin/su",
        "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su",
        "/system/bin/.ext/.su", "/system/usr/we-need-root/su-backup", "/system/xbin/daemonsu"
      )
    )
    val root = kit(many).snapshot().single()
    assertEquals(8, (root.metadata["artifacts"] as List<*>).size)
  }

  @Test
  fun instrumentationFromMappingsIsDeduplicatedAndBounded() {
    val maps = listOf(
      "7f00-7f01 r-xp 0 00:00 0 /data/local/tmp/frida-agent-64.so",
      "7f02-7f03 r-xp 0 00:00 0 /data/local/tmp/frida-agent-64.so (deleted)",
      "7f04-7f05 r-xp 0 00:00 0 /system/lib64/libc.so",
      "7f06-7f07 r--p 0 00:00 0",
      "7f08-7f09 r-xp 0 00:00 0 /data/app/lsposed.so"
    )
    val signal = kit(FakeFiles(contents = mapOf("/proc/self/maps" to maps))).snapshot().single()
    assertEquals(HardeningSignalType.INSTRUMENTATION, signal.type)
    assertEquals(
      listOf("/data/local/tmp/frida-agent-64.so", "/data/app/lsposed.so"),
      signal.metadata["artifacts"]
    )
    assertEquals(0, signal.metadata["tracerPort"])
  }

  @Test
  fun instrumentationFromFridaListeningPort() {
    val tcp = listOf(
      "  sl  local_address rem_address   st",
      "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000",
      "   1: 0100007F:69A2 00000000:0000 01 00000000:00000000",
      "   2: bad",
      "   3: 0100007F:69A3 00000000:0000 0A 00000000:00000000"
    )
    val signal = kit(FakeFiles(contents = mapOf("/proc/net/tcp" to tcp))).snapshot().single()
    assertEquals(HardeningSignalType.INSTRUMENTATION, signal.type)
    assertEquals(27043, signal.metadata["tracerPort"])
    assertEquals(emptyList<String>(), signal.metadata["artifacts"])
  }

  @Test
  fun listeningNonFridaPortIsIgnored() {
    val tcp = listOf(
      "  sl  local_address rem_address   st",
      "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000"
    )
    assertEquals(emptyList<HardeningSignal>(), kit(FakeFiles(contents = mapOf("/proc/net/tcp" to tcp))).snapshot())
  }

  @Test
  fun emulatorNeedsTwoIndicators() {
    setBuild("HARDWARE", "goldfish")
    assertEquals(emptyList<HardeningSignal>(), kit().snapshot())
    setBuild("FINGERPRINT", "generic/sdk_gphone/emulator:14")
    val signal = kit().snapshot().single()
    assertEquals(HardeningSignalType.EMULATOR, signal.type)
    assertEquals(3, signal.metadata["indicatorCount"])
  }

  @Test
  fun emulatorFromModelAndManufacturerIndicators() {
    setBuild("MODEL", "Android SDK built for arm64")
    setBuild("MANUFACTURER", "Genymotion")
    setBuild("PRODUCT", "sdk_gphone64")
    setBuild("HARDWARE", "ranchu")
    assertEquals(4, kit().snapshot().single().metadata["indicatorCount"])
  }

  @Test
  fun accessibilityIgnoresOwnAndTrustedPackages() {
    Settings.Secure.putString(
      context.contentResolver,
      Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES,
      "${context.packageName}/.Own:com.trusted/.Service:com.unknown/.A:com.unknown/.B: "
    )
    val quiet = kit().snapshot(HardeningConfig(trustedAccessibilityPackages = setOf("com.trusted", "com.unknown")))
    assertEquals(emptyList<HardeningSignal>(), quiet)

    val signal = kit().snapshot(HardeningConfig(trustedAccessibilityPackages = setOf("com.trusted"))).single()
    assertEquals(HardeningSignalType.ACCESSIBILITY_UNRECOGNIZED, signal.type)
    assertEquals(1, signal.metadata["serviceCount"])
  }

  @Test
  fun developerOptionsAndAdbAreReportedIndependently() {
    Settings.Global.putInt(context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 1)
    var signal = kit().snapshot().single()
    assertEquals(HardeningSignalType.DEV_MODE_ENABLED, signal.type)
    assertEquals(true, signal.metadata["developerOptions"])
    assertEquals(false, signal.metadata["usbDebugging"])

    Settings.Global.putInt(context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0)
    Settings.Global.putInt(context.contentResolver, Settings.Global.ADB_ENABLED, 1)
    signal = kit().snapshot().single()
    assertEquals(false, signal.metadata["developerOptions"])
    assertEquals(true, signal.metadata["usbDebugging"])
  }

  @Test
  fun signatureCheckIsSkippedWithoutExpectedCertificate() {
    assertEquals(emptyList<HardeningSignal>(), kit().snapshot(HardeningConfig()))
  }

  @Test
  fun signatureUnavailableIsReportedAsMismatch() {
    val signal = kit().snapshot(HardeningConfig(expectedSigningCertificateSha256 = "ab".repeat(32))).single()
    assertEquals(HardeningSignalType.SIGNATURE_MISMATCH, signal.type)
    assertEquals(false, signal.metadata["certificateAvailable"])
  }

  @Test
  @Config(sdk = [27])
  fun signatureMatchesIgnoringColonsAndCase() {
    val bytes = byteArrayOf(1, 2, 3, 4)
    installSigned(bytes)
    val digest = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    val colonUpper = digest.chunked(2).joinToString(":").uppercase()
    assertEquals(emptyList<HardeningSignal>(), kit().snapshot(HardeningConfig(expectedSigningCertificateSha256 = colonUpper)))
    assertEquals(emptyList<HardeningSignal>(), kit().snapshot(HardeningConfig(expectedSigningCertificateSha256 = digest)))
  }

  @Test
  @Config(sdk = [27])
  fun signatureMismatchReportsAvailableCertificate() {
    installSigned(byteArrayOf(1, 2, 3, 4))
    val signal = kit().snapshot(HardeningConfig(expectedSigningCertificateSha256 = "00".repeat(32))).single()
    assertEquals(HardeningSignalType.SIGNATURE_MISMATCH, signal.type)
    assertEquals(true, signal.metadata["certificateAvailable"])
  }

  @Test
  @Config(sdk = [27])
  fun anExtraForgedSignerIsAMismatch() {
    val genuine = byteArrayOf(1, 2, 3, 4)
    installSigned(genuine, byteArrayOf(9, 9, 9))
    val digest = MessageDigest.getInstance("SHA-256").digest(genuine).joinToString("") { "%02x".format(it) }
    val signal = kit().snapshot(HardeningConfig(expectedSigningCertificateSha256 = digest)).single()
    assertEquals(HardeningSignalType.SIGNATURE_MISMATCH, signal.type)
    assertEquals(true, signal.metadata["certificateAvailable"])
  }

  @Suppress("DEPRECATION")
  private fun installSigned(vararg certificates: ByteArray) {
    shadowOf(context.packageManager).installPackage(
      PackageInfo().apply {
        packageName = context.packageName
        signatures = certificates.map { Signature(it) }.toTypedArray()
      }
    )
  }

  @Test
  @Config(shadows = [PresentationDisplayManagerShadow::class])
  fun externalPresentationDisplaysAreCounted() {
    val signals = { kit().snapshot() }
    assertEquals("only the default display exists", emptyList<HardeningSignal>(), signals())

    ShadowDisplayManager.addDisplay("w800dp-h480dp")
    val signal = signals().single()
    assertEquals(HardeningSignalType.EXTERNAL_DISPLAY, signal.type)
    assertEquals(1, signal.metadata["displayCount"])
  }

  @Test
  fun displayChangesAreDeliveredOnlyWhileObserving() {
    val kit = kit()
    val received = mutableListOf<HardeningSignal>()
    kit.startObserving { received += it }
    val id = ShadowDisplayManager.addDisplay("w800dp-h480dp")
    shadowOf(android.os.Looper.getMainLooper()).idle()
    ShadowDisplayManager.changeDisplay(id, "w1024dp-h600dp")
    ShadowDisplayManager.removeDisplay(id)
    shadowOf(android.os.Looper.getMainLooper()).idle()
    assertTrue(received.isNotEmpty())
    received.forEach {
      assertEquals(HardeningSignalType.EXTERNAL_DISPLAY, it.type)
      assertNotNull(it.metadata["connected"])
      assertNotNull(it.metadata["displayCount"])
    }

    kit.stopObserving()
    val before = received.size
    ShadowDisplayManager.addDisplay("w800dp-h480dp")
    shadowOf(android.os.Looper.getMainLooper()).idle()
    assertEquals(before, received.size)
  }

  @Test
  fun stopObservingIsSafeWhenNotObserving() {
    kit().stopObserving()
  }

  @Test
  fun screenProtectionTogglesFlagSecureOnAttachedActivity() {
    val activity = Robolectric.buildActivity(Activity::class.java).setup().get()
    val kit = kit()
    kit.attachActivity(activity)
    assertFalse(isSecure(activity))

    kit.setScreenProtectionEnabled(true)
    assertTrue(isSecure(activity))
    kit.setScreenProtectionEnabled(false)
    assertFalse(isSecure(activity))

    kit.setScreenProtectionEnabled(true)
    kit.detachActivity()
    assertFalse("detach restores the original non-secure state", isSecure(activity))
  }

  @Test
  fun alreadySecureWindowStaysSecure() {
    val activity = Robolectric.buildActivity(Activity::class.java).setup().get()
    activity.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    val kit = kit()
    kit.attachActivity(activity)
    kit.setScreenProtectionEnabled(true)
    kit.setScreenProtectionEnabled(false)
    assertTrue(isSecure(activity))
    kit.detachActivity()
    assertTrue(isSecure(activity))
  }

  @Test
  fun protectionRequestedBeforeAttachAppliesOnAttach() {
    val activity = Robolectric.buildActivity(Activity::class.java).setup().get()
    val kit = kit()
    kit.setScreenProtectionEnabled(true)
    kit.attachActivity(activity)
    assertTrue(isSecure(activity))
  }

  @Test
  fun detachWithoutAttachIsSafe() {
    kit().detachActivity()
  }

  @Test
  @Config(sdk = [34])
  fun screenshotCallbackEmitsWhileObservingAndIsReleasedOnStop() {
    val activity = Robolectric.buildActivity(Activity::class.java).setup().get()
    val kit = kit()
    val received = mutableListOf<HardeningSignal>()
    kit.attachActivity(activity)
    kit.startObserving { received += it }
    kit.startObserving { received += it }

    val callback = ReflectionHelpers.getField<Activity.ScreenCaptureCallback?>(kit, "screenshotCallback")
    assertNotNull("callback registered once an activity is attached", callback)
    callback!!.onScreenCaptured()
    val signal = received.single { it.type == HardeningSignalType.SCREENSHOT_TAKEN }
    assertEquals(mapOf("source" to "systemCallback"), signal.metadata)

    kit.stopObserving()
    assertNull(ReflectionHelpers.getField<Any?>(kit, "screenshotCallback"))
    kit.detachActivity()
  }

  @Test
  @Config(sdk = [34])
  fun observingBeforeAttachRegistersCallbackOnAttach() {
    val activity = Robolectric.buildActivity(Activity::class.java).setup().get()
    val kit = kit()
    kit.startObserving { }
    assertNull(ReflectionHelpers.getField<Any?>(kit, "screenshotCallback"))
    kit.attachActivity(activity)
    assertNotNull(ReflectionHelpers.getField<Any?>(kit, "screenshotCallback"))
    kit.detachActivity()
    assertNull(ReflectionHelpers.getField<Any?>(kit, "screenshotCallback"))
  }

  @Test
  @Config(sdk = [33])
  fun screenshotCallbackIsNotRegisteredBeforeAndroid14() {
    val activity = Robolectric.buildActivity(Activity::class.java).setup().get()
    val kit = kit()
    kit.attachActivity(activity)
    kit.startObserving { }
    assertNull(ReflectionHelpers.getField<Any?>(kit, "screenshotCallback"))
  }

  @Test
  fun systemFilesReadRealFiles() {
    val file = java.io.File.createTempFile("hardening", ".txt").apply {
      writeText("a\nb\n")
      deleteOnExit()
    }
    assertTrue(SystemFiles.exists(file.path))
    assertFalse(SystemFiles.exists(file.path + ".missing"))
    assertEquals(listOf("a", "b"), SystemFiles.readLines(file.path))
  }

  private fun isSecure(activity: Activity) =
    (activity.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE) != 0
}
