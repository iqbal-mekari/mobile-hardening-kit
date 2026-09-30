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
import com.mekari.mobile_hardening_kit.MobileHardeningKit

/**
 * Minimal native (no Flutter) consumer: snapshot, event observation, and opt-in screen protection.
 * Signals are reported for display only; this sample makes no allow/deny decision.
 */
class MainActivity : Activity() {
  private lateinit var kit: MobileHardeningKit
  private lateinit var snapshotView: TextView
  private lateinit var eventsView: TextView
  private val events = ArrayDeque<HardeningSignal>()

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

  private fun describe(signal: HardeningSignal) =
    "${signal.type} @ ${signal.observedAt}\n${signal.metadata}"

  private fun buildUi(): ScrollView {
    val pad = (16 * resources.displayMetrics.density).toInt()
    snapshotView = TextView(this)
    eventsView = TextView(this).apply { text = "Waiting for display/capture events..." }
    val column = LinearLayout(this).apply {
      orientation = LinearLayout.VERTICAL
      setPadding(pad, pad, pad, pad)
      addView(Button(this@MainActivity).apply {
        text = "Scan now"
        setOnClickListener { scan() }
      })
      addView(Switch(this@MainActivity).apply {
        text = "Screen protection (FLAG_SECURE)"
        setOnCheckedChangeListener { _, enabled -> kit.setScreenProtectionEnabled(enabled) }
      })
      addView(header("Snapshot"))
      addView(snapshotView)
      addView(header("Events"))
      addView(eventsView)
    }
    return ScrollView(this).apply { addView(column, MATCH_PARENT, WRAP_CONTENT) }
  }

  private fun header(title: String) = TextView(this).apply {
    text = title
    textSize = 18f
    setPadding(0, (16 * resources.displayMetrics.density).toInt(), 0, 0)
  }
}
