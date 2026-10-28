package com.mekari.mobile_hardening_kit

import android.app.Activity
import android.app.Application
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import java.util.concurrent.Executor
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/** Inputs for [MobileHardeningKit.startMonitoring]. The effective interval is at least 5 seconds. */
data class IntegrityMonitorConfig(
  /** Runtime-attach check period while the attached activity is started. */
  val intervalMs: Long = 30_000,
  /** Run a full pass when the attached activity returns to the foreground. */
  val checkOnResume: Boolean = true
)

internal enum class IntegrityTier { FULL, RUNTIME }

/** Threading and timing seams for [IntegrityMonitor]; replaceable in tests. */
internal class MonitorEnv(
  /** Runs passes; must execute tasks one at a time, in order. */
  val background: Executor,
  /** Delivers results on the main thread. */
  val main: (Runnable) -> Unit,
  /** Runs the task once after the delay on the main thread; returns a cancel function. */
  val timer: (Long, Runnable) -> () -> Unit,
  val release: () -> Unit = {}
) {
  companion object {
    fun system(): MonitorEnv {
      val handler = Handler(Looper.getMainLooper())
      val executor: ExecutorService = Executors.newSingleThreadExecutor { task ->
        Thread(task, "mhk-integrity").apply { isDaemon = true }
      }
      return MonitorEnv(
        background = executor,
        main = { handler.post(it) },
        timer = { delayMs, task ->
          handler.postDelayed(task, delayMs)
          val cancel: () -> Unit = { handler.removeCallbacks(task) }
          cancel
        },
        release = { executor.shutdown() }
      )
    }
  }
}

/**
 * Re-runs detectors on a schedule and reports only changes. One instance is one monitoring session; main
 * thread only, except for [scan] and diffing, which run on the single background executor.
 */
internal class IntegrityMonitor(
  config: IntegrityMonitorConfig,
  private val env: MonitorEnv,
  private val listener: HardeningSignalListener,
  private val scan: (IntegrityTier) -> List<HardeningSignal>
) : Application.ActivityLifecycleCallbacks {
  private val intervalMs = maxOf(config.intervalMs, MIN_INTERVAL_MS)
  private val checkOnResume = config.checkOnResume
  private var active = true
  private var paused = false
  private var cancelTimer: (() -> Unit)? = null
  private var activity: Activity? = null
  private var application: Application? = null

  // Touched only on the background executor.
  private val last = mutableMapOf<String, Pair<String, Map<String, Any>>>()

  fun start(target: Activity?) {
    target?.let(::bind)
    submit(IntegrityTier.FULL, "start")
    scheduleTick()
  }

  fun checkNow() = submit(IntegrityTier.FULL, "manual")

  fun stop() {
    if (!active) return
    active = false
    cancelTimer?.invoke()
    cancelTimer = null
    unbind()
    env.release()
  }

  /** A newly attached activity is assumed foregrounded; returning from a pause counts as a resume. */
  fun onAttach(target: Activity) {
    unbind()
    bind(target)
    if (paused) resume()
  }

  /** The interval stays paused if it was paused, until an activity attaches again. */
  fun onDetach() = unbind()

  private fun bind(target: Activity) {
    activity = target
    application = target.application.also { it.registerActivityLifecycleCallbacks(this) }
  }

  private fun unbind() {
    application?.unregisterActivityLifecycleCallbacks(this)
    application = null
    activity = null
  }

  private fun pause() {
    paused = true
    cancelTimer?.invoke()
    cancelTimer = null
  }

  private fun resume() {
    paused = false
    if (checkOnResume) submit(IntegrityTier.FULL, "resume")
    scheduleTick()
  }

  private fun scheduleTick() {
    cancelTimer?.invoke()
    cancelTimer = env.timer(intervalMs) {
      submit(IntegrityTier.RUNTIME, "interval")
      scheduleTick()
    }
  }

  private fun submit(tier: IntegrityTier, trigger: String) {
    env.background.execute {
      val events = diff(tier, trigger, scan(tier))
      if (events.isNotEmpty()) env.main(Runnable { if (active) events.forEach(listener::onSignal) })
    }
  }

  private fun diff(tier: IntegrityTier, trigger: String, found: List<HardeningSignal>): List<HardeningSignal> {
    val covered = if (tier == IntegrityTier.FULL) FULL_TYPES else RUNTIME_TYPES
    val events = mutableListOf<HardeningSignal>()
    fun event(type: String, at: String, metadata: Map<String, Any>, change: String) {
      events += HardeningSignal(type, at, metadata + mapOf("change" to change, "trigger" to trigger))
    }
    for (signal in found) {
      val key = keyOf(signal)
      val previous = last[signal.type]
      last[signal.type] = key to signal.metadata
      if (previous == null) event(signal.type, signal.observedAt, signal.metadata, "detected")
      else if (previous.first != key) event(signal.type, signal.observedAt, signal.metadata, "changed")
    }
    val foundTypes = found.map { it.type }.toSet()
    for (type in covered) {
      if (type in foundTypes) continue
      val previous = last.remove(type) ?: continue
      event(type, isoTimestamp(), previous.second, "cleared")
    }
    return events
  }

  /** Signal type + sorted techniques + sorted artifacts; timestamps and counters are excluded. */
  private fun keyOf(signal: HardeningSignal): String {
    fun sorted(name: String) = (signal.metadata[name] as? List<*>).orEmpty().map { it.toString() }.sorted()
    return listOf(signal.type, sorted("techniques"), sorted("artifacts")).joinToString("|")
  }

  private fun ours(target: Activity) = target === activity

  override fun onActivityStarted(target: Activity) {
    if (active && ours(target) && paused) resume()
  }

  override fun onActivityStopped(target: Activity) {
    if (active && ours(target)) pause()
  }

  override fun onActivityCreated(target: Activity, savedInstanceState: Bundle?) = Unit
  override fun onActivityResumed(target: Activity) = Unit
  override fun onActivityPaused(target: Activity) = Unit
  override fun onActivitySaveInstanceState(target: Activity, outState: Bundle) = Unit
  override fun onActivityDestroyed(target: Activity) = Unit

  private companion object {
    const val MIN_INTERVAL_MS = 5_000L
    val RUNTIME_TYPES = listOf(HardeningSignalType.INSTRUMENTATION, HardeningSignalType.DEBUGGER_ATTACH)
    val FULL_TYPES = listOf(
      HardeningSignalType.ROOT, HardeningSignalType.INSTRUMENTATION, HardeningSignalType.DEBUGGER_ATTACH,
      HardeningSignalType.SIGNATURE_MISMATCH, HardeningSignalType.EMULATOR,
      HardeningSignalType.ACCESSIBILITY_UNRECOGNIZED, HardeningSignalType.DEV_MODE_ENABLED,
      HardeningSignalType.EXTERNAL_DISPLAY
    )
  }
}
