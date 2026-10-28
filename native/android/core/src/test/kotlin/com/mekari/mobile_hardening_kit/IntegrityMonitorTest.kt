package com.mekari.mobile_hardening_kit

import android.app.Activity
import android.content.Context
import android.os.Build
import android.os.Looper
import android.provider.Settings
import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.util.ReflectionHelpers

/** Manually driven background executor, main poster and timer. */
private class FakeEnv {
  class Timer(val delayMs: Long, val task: Runnable) {
    var cancelled = false
    var fired = false
  }

  val background = mutableListOf<Runnable>()
  val main = mutableListOf<Runnable>()
  val timers = mutableListOf<Timer>()
  var released = 0

  fun env() = MonitorEnv(
    background = Executor { background += it },
    main = { main += it },
    timer = { delay, task ->
      val timer = Timer(delay, task)
      timers += timer
      val cancel: () -> Unit = { timer.cancelled = true }
      cancel
    },
    release = { released++ }
  )

  fun runBackground() {
    while (background.isNotEmpty()) background.removeAt(0).run()
  }

  fun runMain() {
    while (main.isNotEmpty()) main.removeAt(0).run()
  }

  fun flush() {
    runBackground()
    runMain()
  }

  fun pending() = timers.filter { !it.cancelled && !it.fired }

  fun fire() {
    val timer = pending().single()
    timer.fired = true
    timer.task.run()
  }
}

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33], shadows = [DebugShadow::class])
class IntegrityMonitorTest {
  private lateinit var context: Context
  private val fake = FakeEnv()
  private val received = mutableListOf<HardeningSignal>()
  private val tiers = mutableListOf<IntegrityTier>()
  private var scanned: List<HardeningSignal> = emptyList()

  private val originalTags = ReflectionHelpers.getStaticField<Any?>(Build::class.java, "TAGS")

  @Before
  fun setUp() {
    context = RuntimeEnvironment.getApplication()
    ReflectionHelpers.setStaticField(Build::class.java, "TAGS", "release-keys")
    DebugShadow.connected = false
    DebugShadow.waiting = false
  }

  @After
  fun tearDown() {
    ReflectionHelpers.setStaticField(Build::class.java, "TAGS", originalTags)
  }

  private fun sig(type: String, techniques: List<String> = emptyList(), artifacts: List<String> = emptyList(), extra: Int = 0) =
    HardeningSignal(
      type, "2026-01-01T00:00:00.000Z",
      mapOf("techniques" to techniques, "artifacts" to artifacts, "count" to extra)
    )

  private val root get() = sig(HardeningSignalType.ROOT, listOf("paths"), listOf("/sbin/su"))
  private val frida get() = sig(HardeningSignalType.INSTRUMENTATION, listOf("maps"), listOf("/a", "/b"))

  private fun monitor(config: IntegrityMonitorConfig = IntegrityMonitorConfig()) =
    IntegrityMonitor(config, fake.env(), { received += it }) { tier ->
      tiers += tier
      scanned
    }

  private fun changes() = received.map { Triple(it.type, it.metadata["change"], it.metadata["trigger"]) }

  @Test
  fun screenAndDisplayTypesNeverReachTheIntegrityStreamNorClear() {
    val display = sig(HardeningSignalType.EXTERNAL_DISPLAY)
    val capture = sig(HardeningSignalType.SCREEN_CAPTURE_ACTIVE)
    scanned = listOf(root, display, capture)
    val monitor = monitor()
    monitor.start(null)
    fake.flush()
    assertEquals(listOf(Triple("root", "detected", "start")), changes())

    scanned = listOf(root)
    monitor.checkNow()
    scanned = listOf(root, display)
    monitor.checkNow()
    fake.flush()
    assertEquals(1, received.size)
    monitor.stop()
  }

  // --- diffing ----------------------------------------------------------------------------------

  @Test
  fun firstPassReportsEverythingAsDetectedWithTriggerAndDeliversOnTheMainQueue() {
    scanned = listOf(root, frida)
    monitor().start(null)
    fake.runBackground()
    assertTrue("nothing is delivered before the main poster runs", received.isEmpty())
    fake.runMain()
    assertEquals(
      listOf(
        Triple("root", "detected", "start"),
        Triple("instrumentation", "detected", "start")
      ),
      changes()
    )
    assertEquals(listOf("paths"), received[0].metadata["techniques"])
    assertEquals(listOf(IntegrityTier.FULL), tiers)
  }

  @Test
  fun anEmptyFirstPassDeliversNothing() {
    monitor().start(null)
    fake.flush()
    assertTrue(fake.main.isEmpty())
    assertTrue(received.isEmpty())
  }

  @Test
  fun sameKeyIsSilentAndCountersAndOrderDoNotCount() {
    val m = monitor()
    scanned = listOf(frida)
    m.start(null)
    fake.flush()
    received.clear()
    scanned = listOf(sig(HardeningSignalType.INSTRUMENTATION, listOf("maps"), listOf("/b", "/a"), extra = 9))
    m.checkNow()
    fake.flush()
    assertTrue(received.isEmpty())
  }

  @Test
  fun changedTechniquesOrArtifactsEmitChanged() {
    val m = monitor()
    scanned = listOf(frida)
    m.start(null)
    fake.flush()
    received.clear()
    scanned = listOf(sig(HardeningSignalType.INSTRUMENTATION, listOf("maps", "threadName"), listOf("/a", "/b")))
    m.checkNow()
    fake.flush()
    scanned = listOf(sig(HardeningSignalType.INSTRUMENTATION, listOf("maps", "threadName"), listOf("/a")))
    m.checkNow()
    fake.flush()
    assertEquals(
      listOf(
        Triple("instrumentation", "changed", "manual"),
        Triple("instrumentation", "changed", "manual")
      ),
      changes()
    )
  }

  @Test
  fun typesWithoutTechniquesKeyOnTypeAlone() {
    val m = monitor()
    scanned = listOf(HardeningSignal(HardeningSignalType.EMULATOR, "t", mapOf("indicatorCount" to 2)))
    m.start(null)
    fake.flush()
    received.clear()
    scanned = listOf(HardeningSignal(HardeningSignalType.EMULATOR, "t2", mapOf("indicatorCount" to 3)))
    m.checkNow()
    fake.flush()
    assertTrue(received.isEmpty())
  }

  @Test
  fun clearedCarriesTheLastMetadataAndAFreshTimestamp() {
    val m = monitor()
    scanned = listOf(frida)
    m.start(null)
    fake.flush()
    received.clear()
    scanned = emptyList()
    m.checkNow()
    fake.flush()
    val cleared = received.single()
    assertEquals("cleared", cleared.metadata["change"])
    assertEquals("manual", cleared.metadata["trigger"])
    assertEquals(listOf("maps"), cleared.metadata["techniques"])
    assertEquals(listOf("/a", "/b"), cleared.metadata["artifacts"])
    assertNotEquals("2026-01-01T00:00:00.000Z", cleared.observedAt)
    received.clear()
    m.checkNow()
    fake.flush()
    assertTrue("a cleared finding is not cleared twice", received.isEmpty())
  }

  @Test
  fun aRuntimePassNeverClearsRootButAFullPassDoes() {
    val m = monitor(IntegrityMonitorConfig(intervalMs = 10_000))
    scanned = listOf(root, frida)
    m.start(startedActivity().get())
    fake.flush()
    received.clear()

    scanned = listOf(frida)
    fake.fire()
    fake.flush()
    assertTrue(received.isEmpty())
    assertEquals(IntegrityTier.RUNTIME, tiers.last())

    scanned = listOf(frida, sig(HardeningSignalType.DEBUGGER_ATTACH, listOf("tracerPid")))
    fake.fire()
    fake.flush()
    assertEquals(listOf(Triple("debuggerAttach", "detected", "interval")), changes())
    received.clear()

    scanned = listOf(frida)
    m.checkNow()
    fake.flush()
    assertEquals(
      listOf(Triple("root", "cleared", "manual"), Triple("debuggerAttach", "cleared", "manual")),
      changes()
    )
  }

  // --- scheduling -------------------------------------------------------------------------------

  @Test
  fun intervalDefaultsAndClampsAndReschedulesAfterEachTick() {
    monitor().start(startedActivity().get())
    assertEquals(30_000L, fake.pending().single().delayMs)
    fake.fire()
    assertEquals(30_000L, fake.pending().single().delayMs)

    val clamped = FakeEnv()
    IntegrityMonitor(IntegrityMonitorConfig(intervalMs = 1_000), clamped.env(), { }) { emptyList() }.start(startedActivity().get())
    assertEquals(5_000L, clamped.pending().single().delayMs)

    val huge = FakeEnv()
    IntegrityMonitor(IntegrityMonitorConfig(intervalMs = Long.MAX_VALUE), huge.env(), { }) { emptyList() }
      .start(startedActivity().get())
    assertEquals(86_400_000L, huge.pending().single().delayMs)
    val negative = FakeEnv()
    IntegrityMonitor(IntegrityMonitorConfig(intervalMs = Long.MIN_VALUE), negative.env(), { }) { emptyList() }
      .start(startedActivity().get())
    assertEquals(5_000L, negative.pending().single().delayMs)
    assertEquals(IntegrityMonitorConfig(30_000, true), IntegrityMonitorConfig())
  }

  @Test
  fun stopCancelsTheTimerDropsQueuedResultsAndIsIdempotent() {
    val m = monitor()
    scanned = listOf(root)
    m.start(null)
    fake.runBackground()
    m.stop()
    fake.runMain()
    assertTrue("results queued before stop are dropped", received.isEmpty())
    assertTrue(fake.pending().isEmpty())
    m.stop()
    assertEquals(1, fake.released)
  }

  // --- lifecycle --------------------------------------------------------------------------------

  private fun startedActivity() = Robolectric.buildActivity(Activity::class.java).setup()

  @Test
  fun intervalPausesWhileTheActivityIsStoppedAndResumesWithAFullPass() {
    val controller = startedActivity()
    val m = monitor()
    scanned = listOf(frida)
    m.start(controller.get())
    fake.flush()
    received.clear()
    tiers.clear()

    controller.pause().stop()
    assertTrue("interval paused", fake.pending().isEmpty())

    scanned = listOf(frida, root)
    controller.restart().start()
    fake.flush()
    assertEquals(listOf(Triple("root", "detected", "resume")), changes())
    assertEquals(listOf(IntegrityTier.FULL), tiers)
    assertEquals(1, fake.pending().size)

    received.clear()
    controller.resume()
    fake.flush()
    assertTrue("a start while running is not a resume", received.isEmpty())
    m.stop()
  }

  @Test
  fun resumeWithoutCheckOnResumeOnlyRestartsTheInterval() {
    val controller = startedActivity()
    val m = monitor(IntegrityMonitorConfig(checkOnResume = false))
    m.start(controller.get())
    fake.flush()
    tiers.clear()
    controller.pause().stop()
    controller.restart().start()
    fake.flush()
    assertTrue(tiers.isEmpty())
    assertEquals(1, fake.pending().size)
    m.stop()
  }

  @Test
  fun otherActivitiesAreIgnored() {
    val ours = startedActivity()
    val other = startedActivity()
    val m = monitor()
    m.start(ours.get())
    m.onActivityStopped(other.get())
    assertEquals(1, fake.pending().size)
    m.onActivityStopped(ours.get())
    assertTrue(fake.pending().isEmpty())
    m.onActivityStarted(other.get())
    assertTrue(fake.pending().isEmpty())
    m.stop()
    m.onActivityStarted(ours.get())
    assertTrue("callbacks after stop do nothing", fake.pending().isEmpty())
    // Unused lifecycle callbacks are no-ops.
    m.onActivityCreated(ours.get(), null)
    m.onActivityResumed(ours.get())
    m.onActivityPaused(ours.get())
    m.onActivitySaveInstanceState(ours.get(), android.os.Bundle())
    m.onActivityDestroyed(ours.get())
  }

  @Test
  fun detachUnregistersTheLifecycleCallbacksAndAttachRebindsAndResumes() {
    val first = startedActivity()
    val second = startedActivity()
    val m = monitor()
    m.start(first.get())
    fake.flush()
    tiers.clear()

    m.onDetach()
    first.pause().stop()
    assertEquals("no longer listening to the detached activity", 1, fake.pending().size)

    m.onAttach(second.get())
    fake.flush()
    assertTrue("attach while running is not a resume", tiers.isEmpty())
    second.pause().stop()
    assertTrue(fake.pending().isEmpty())

    m.onDetach()
    assertTrue("detach keeps a paused monitor paused", fake.pending().isEmpty())
    m.onAttach(second.get())
    fake.flush()
    assertEquals(listOf(IntegrityTier.FULL), tiers)
    assertEquals(1, fake.pending().size)
    m.stop()
  }

  @Test
  fun startedWithoutAnActivityRunsTheStartPassButDoesNotTickUntilOneAttaches() {
    val m = monitor()
    scanned = listOf(frida)
    m.start(null)
    fake.flush()
    assertEquals(listOf(IntegrityTier.FULL), tiers)
    assertTrue("foreground only: no timer without an activity", fake.pending().isEmpty())

    m.onAttach(startedActivity().get())
    fake.flush()
    assertEquals(listOf(IntegrityTier.FULL, IntegrityTier.FULL), tiers)
    assertEquals(1, fake.pending().size)
    fake.fire()
    fake.flush()
    assertEquals(IntegrityTier.RUNTIME, tiers.last())
    m.onDetach()
    m.stop()
  }

  @Test
  fun attachingAfterANullStartResumesWithoutAPassWhenCheckOnResumeIsOff() {
    val m = monitor(IntegrityMonitorConfig(checkOnResume = false))
    m.start(null)
    fake.flush()
    tiers.clear()
    m.onAttach(startedActivity().get())
    fake.flush()
    assertTrue(tiers.isEmpty())
    assertEquals(1, fake.pending().size)
    m.stop()
  }

  @Test
  fun aStartOfTheAttachedActivityResumesAMonitorStartedWithoutAnActivity() {
    val controller = startedActivity()
    val m = monitor()
    m.start(null)
    m.onActivityStarted(controller.get())
    assertTrue("not ours until attached", fake.pending().isEmpty())
    m.onAttach(controller.get())
    controller.pause().stop()
    assertTrue(fake.pending().isEmpty())
    controller.restart().start()
    assertEquals(1, fake.pending().size)
    m.stop()
  }

  @Test
  fun destroyingTheAttachedActivityUnbindsAndPausesButOtherActivitiesAreIgnored() {
    val ours = startedActivity()
    val other = startedActivity()
    val m = monitor()
    m.start(ours.get())
    m.onActivityDestroyed(other.get())
    assertEquals(1, fake.pending().size)

    ours.pause().stop().destroy()
    assertTrue(fake.pending().isEmpty())
    m.onActivityStarted(ours.get())
    assertTrue("a late start of the destroyed activity is ignored", fake.pending().isEmpty())
    m.onAttach(other.get())
    assertEquals(1, fake.pending().size)
    m.stop()
  }

  // --- kit integration --------------------------------------------------------------------------

  private fun kit(files: FileAccess = FakeFiles()) = MobileHardeningKit(context, files, fake::env)

  private fun fridaFiles() = FakeFiles(
    contents = mapOf("/proc/self/maps" to listOf("7f00-7f01 r--p 0 00:01 0 /data/frida-agent.so"))
  )

  @Test
  fun kitMonitoringRunsTiersAndAppliesTheHardeningConfig() {
    val files = fridaFiles()
    val kit = kit(files)
    kit.attachActivity(startedActivity().get())
    kit.startMonitoring(
      IntegrityMonitorConfig(),
      { received += it },
      HardeningConfig(expectedSigningCertificateSha256 = "ab".repeat(32))
    )
    fake.flush()
    assertEquals(
      listOf("instrumentation", "signatureMismatch"),
      received.map { it.type }
    )
    assertTrue(received.all { it.metadata["change"] == "detected" && it.metadata["trigger"] == "start" })
    received.clear()

    files.contents["/proc/self/maps"] = emptyList()
    fake.fire()
    fake.flush()
    assertEquals(listOf(Triple("instrumentation", "cleared", "interval")), changes())
    kit.stopMonitoring()
  }

  @Test
  fun checkIntegrityNowRunsAManualFullPassOnlyWhileMonitoring() {
    val files = FakeFiles()
    val kit = kit(files)
    kit.checkIntegrityNow()
    assertTrue(fake.background.isEmpty())

    kit.startMonitoring(IntegrityMonitorConfig(), { received += it })
    fake.flush()
    files.contents["/proc/self/status"] = listOf("TracerPid:\t9")
    kit.checkIntegrityNow()
    fake.flush()
    assertEquals(listOf(Triple("debuggerAttach", "detected", "manual")), changes())

    kit.stopMonitoring()
    kit.checkIntegrityNow()
    assertTrue(fake.background.isEmpty())
    kit.stopMonitoring()
  }

  @Test
  fun startingAgainReplacesTheSessionAndRestartsFromScratch() {
    val kit = kit(fridaFiles())
    kit.attachActivity(startedActivity().get())
    val old = mutableListOf<HardeningSignal>()
    kit.startMonitoring(IntegrityMonitorConfig(), { old += it })
    fake.runBackground()
    kit.startMonitoring(IntegrityMonitorConfig(), { received += it })
    fake.flush()
    assertTrue("the replaced session delivers nothing", old.isEmpty())
    assertEquals(listOf(Triple("instrumentation", "detected", "start")), changes())
    assertEquals(1, fake.pending().size)
    assertEquals(1, fake.released)
    kit.stopMonitoring()
  }

  @Test
  fun monitoringIsIndependentOfObserving() {
    val kit = kit(fridaFiles())
    val screen = mutableListOf<HardeningSignal>()
    kit.startMonitoring(IntegrityMonitorConfig(), { received += it })
    kit.startObserving { screen += it }
    fake.flush()
    assertTrue(screen.isEmpty())

    kit.stopObserving()
    kit.checkIntegrityNow()
    fake.flush()
    assertEquals(1, received.size)

    kit.startObserving { screen += it }
    kit.stopMonitoring()
    kit.onDisplayChanged(1)
    assertEquals(HardeningSignalType.EXTERNAL_DISPLAY, screen.single().type)
    kit.stopObserving()
  }

  @Test
  fun kitForwardsActivityAttachAndDetachToTheMonitor() {
    val controller = startedActivity()
    val kit = kit()
    kit.startMonitoring(IntegrityMonitorConfig(), { received += it })
    kit.attachActivity(controller.get())
    fake.flush()
    controller.pause().stop()
    assertTrue(fake.pending().isEmpty())

    kit.detachActivity()
    controller.restart().start()
    assertTrue("detached: the lifecycle is no longer observed", fake.pending().isEmpty())
    kit.attachActivity(controller.get())
    assertEquals(1, fake.pending().size)
    kit.detachActivity()
    kit.stopMonitoring()
  }

  @Test
  fun anActivityAttachedBeforeStartIsUsed() {
    val controller = startedActivity()
    val kit = kit()
    kit.attachActivity(controller.get())
    kit.startMonitoring(IntegrityMonitorConfig(), { received += it })
    controller.pause().stop()
    assertTrue(fake.pending().isEmpty())
    kit.detachActivity()
    kit.stopMonitoring()
  }

  @Test
  @Config(sdk = [28, 29, 32, 35]) // API 23: Robolectric cannot initialise android.os.Debug.
  fun aCleanDeviceStaysQuietOnEverySupportedApi() {
    val kit = kit()
    kit.attachActivity(startedActivity().get())
    kit.startMonitoring(IntegrityMonitorConfig(), { received += it })
    fake.flush()
    fake.fire()
    fake.flush()
    val signalTypes = received.map { it.type }
    assertFalse(HardeningSignalType.INSTRUMENTATION in signalTypes)
    assertFalse(HardeningSignalType.DEBUGGER_ATTACH in signalTypes)
    kit.stopMonitoring()
  }

  // --- system environment -----------------------------------------------------------------------

  @Test
  fun systemEnvRunsBackgroundWorkOffTheMainThreadAndPostsToMain() {
    val env = MonitorEnv.system()
    val latch = CountDownLatch(1)
    var backgroundThread: Thread? = null
    env.background.execute {
      backgroundThread = Thread.currentThread()
      latch.countDown()
    }
    assertTrue(latch.await(5, TimeUnit.SECONDS))
    assertNotEquals(Looper.getMainLooper().thread, backgroundThread)
    assertEquals("mhk-integrity", backgroundThread!!.name)

    var posted = false
    env.main(Runnable { posted = true })
    assertFalse(posted)
    shadowOf(Looper.getMainLooper()).idle()
    assertTrue(posted)

    var fired = 0
    val cancel = env.timer(1_000, Runnable { fired++ })
    shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(999))
    assertEquals(0, fired)
    shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(2))
    assertEquals(1, fired)
    val cancelled = env.timer(1_000, Runnable { fired++ })
    cancelled()
    cancel()
    shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(2_000))
    assertEquals(1, fired)

    env.release()
    var rejected = false
    try {
      env.background.execute { }
    } catch (_: RejectedExecutionException) {
      rejected = true
    }
    assertTrue(rejected)
  }

  @Test
  fun publicKitMonitorsWithTheSystemEnvironment() {
    Settings.Global.putInt(context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 1)
    val kit = MobileHardeningKit(context)
    kit.startMonitoring(IntegrityMonitorConfig(), { received += it })
    val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
    while (received.isEmpty() && System.nanoTime() < deadline) {
      shadowOf(Looper.getMainLooper()).idle()
      Thread.sleep(10)
    }
    kit.stopMonitoring()
    assertEquals(listOf(Triple("devModeEnabled", "detected", "start")), changes())
  }
}
