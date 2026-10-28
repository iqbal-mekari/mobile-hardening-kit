package com.mekari.mobile_hardening_kit.sample

import android.app.Activity
import android.os.Bundle
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Switch
import android.widget.TextView
import com.mekari.mobile_hardening_kit.HardeningConfig
import com.mekari.mobile_hardening_kit.HardeningSignal
import com.mekari.mobile_hardening_kit.IntegrityMonitorConfig
import com.mekari.mobile_hardening_kit.MobileHardeningKit
import com.mekari.mobile_hardening_kit.ScreenProtection
import com.mekari.mobile_hardening_kit.ScreenProtectionState

/**
 * Minimal native (no Flutter) consumer: snapshot, event observation, opt-in screen protection, and the opt-in integrity monitor.
 * Signals are reported for display only; this sample makes no allow/deny decision.
 */
class MainActivity : Activity() {
  private lateinit var kit: MobileHardeningKit
  private lateinit var snapshotView: TextView
  private lateinit var eventsView: TextView
  private lateinit var protectionView: TextView
  private lateinit var findingsView: TextView
  private val events = ArrayDeque<HardeningSignal>()
  private val findings = ArrayDeque<HardeningSignal>()

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    kit = MobileHardeningKit(applicationContext)
    kit.attachActivity(this)
    setContentView(buildUi())
    scan()
  }

  // Events run only while visible; the listener is invoked on the main thread.
  override fun onStart() {
    super.onStart()
    kit.startObserving { signal ->
      events.addFirst(signal)
      if (events.size > 20) events.removeLast()
      eventsView.text = events.joinToString("\n\n", transform = ::describe)
    }
  }

  override fun onStop() {
    kit.stopObserving()
    super.onStop()
  }

  // Restores the window's original FLAG_SECURE state.
  override fun onDestroy() {
    kit.stopMonitoring()
    kit.detachActivity()
    super.onDestroy()
  }

  private fun scan() {
    val signals = kit.snapshot(
      HardeningConfig(
        // expectedSigningCertificateSha256 = "<your release cert SHA-256>", // optional
        trustedAccessibilityPackages = emptySet()
      )
    )
    snapshotView.text =
      if (signals.isEmpty()) "No signals observed (not proof of integrity)."
      else signals.joinToString("\n\n", transform = ::describe)
  }

  // Applies the options and shows what the platform actually applied (unavailable lists the gaps).
  private fun protect(enabled: Boolean) {
    val state = kit.setScreenProtection(
      if (enabled) ScreenProtection(blockCapture = true, obscureWhileCaptured = true, obscureAppSwitcher = true)
      else ScreenProtection.OFF
    )
    protectionView.text = describe(state)
  }

  private fun describe(state: ScreenProtectionState) =
    "captureBlocked=${state.captureBlocked}, obscuresWhileCaptured=${state.obscuresWhileCaptured}, " +
      "obscuresAppSwitcher=${state.obscuresAppSwitcher}, unavailable=${state.unavailable}"

  // Report-only and foreground only; findings arrive on the main thread.
  private fun monitor(enabled: Boolean) {
    if (!enabled) {
      kit.stopMonitoring()
      return
    }
    kit.startMonitoring(IntegrityMonitorConfig(intervalMs = 30_000), { signal ->
      findings.addFirst(signal)
      if (findings.size > 20) findings.removeLast()
      findingsView.text = findings.joinToString("\n\n", transform = ::describe)
    })
  }

  private fun describe(signal: HardeningSignal) =
    "${signal.type} @ ${signal.observedAt}\n${signal.metadata}"

  private fun buildUi(): ScrollView {
    val pad = (16 * resources.displayMetrics.density).toInt()
    snapshotView = TextView(this)
    eventsView = TextView(this).apply { text = "Waiting for display/capture events..." }
    protectionView = TextView(this).apply { text = "Protection off." }
    findingsView = TextView(this).apply { text = "Monitor off." }
    val column = LinearLayout(this).apply {
      orientation = LinearLayout.VERTICAL
      setPadding(pad, pad, pad, pad)
      addView(Button(this@MainActivity).apply {
        text = "Scan now"
        setOnClickListener { scan() }
      })
      addView(Switch(this@MainActivity).apply {
        text = "Screen protection (capture, recording, Recents)"
        setOnCheckedChangeListener { _, enabled -> protect(enabled) }
      })
      addView(protectionView)
      addView(Switch(this@MainActivity).apply {
        text = "Integrity monitor"
        setOnCheckedChangeListener { _, enabled -> monitor(enabled) }
      })
      addView(Button(this@MainActivity).apply {
        text = "Check integrity now"
        setOnClickListener { kit.checkIntegrityNow() }
      })
      addView(header("Snapshot"))
      addView(snapshotView)
      addView(header("Events"))
      addView(eventsView)
      addView(header("Integrity findings"))
      addView(findingsView)
    }
    return ScrollView(this).apply {
      fitsSystemWindows = true // targetSdk 35+ draws edge-to-edge; keep content clear of the system bars.
      addView(column, MATCH_PARENT, WRAP_CONTENT)
    }
  }

  private fun header(title: String) = TextView(this).apply {
    text = title
    textSize = 18f
    setPadding(0, (16 * resources.displayMetrics.density).toInt(), 0, 0)
  }
}
