import Foundation
import UIKit

/// Runtime integrity monitor settings.
public struct IntegrityMonitorConfig: Equatable {
  /// The shortest interval the monitor runs at.
  public static let minimumInterval: TimeInterval = 5

  /// Seconds between runtime-tier passes (instrumentation and debugger) while the app is active.
  public var interval: TimeInterval = 30
  /// Runs a full pass whenever the app becomes active again.
  public var checkOnResume = true

  public init(interval: TimeInterval = 30, checkOnResume: Bool = true) {
    self.interval = interval
    self.checkOnResume = checkOnResume
  }

  /// `interval` clamped to at least `minimumInterval` (NaN clamps too).
  public var effectiveInterval: TimeInterval {
    interval >= Self.minimumInterval ? interval : Self.minimumInterval
  }
}

/// Why a monitor pass ran; the `trigger` metadata value.
enum IntegrityTrigger: String {
  case start
  case resume
  case interval
  case manual
  case imageLoad
}

/// How a finding differs from the previous pass; the `change` metadata value.
enum IntegrityChange: String {
  case detected
  case changed
  case cleared
}

/// A repeating timer registration; `cancel()` stops it and is idempotent.
protocol MonitorTimer: AnyObject {
  func cancel()
}

/// Timer, notification, and clock seams of the monitor; replaceable in tests.
struct MonitorEnvironment {
  /// Calls `fire` on the main queue every `interval` seconds until cancelled.
  var scheduleRepeating: (_ interval: TimeInterval, _ fire: @escaping () -> Void) -> MonitorTimer
  var notificationCenter: NotificationCenter
  var now: () -> Date

  static let system = MonitorEnvironment(
    scheduleRepeating: { RunLoopTimer(interval: $0, fire: $1) }, notificationCenter: .default,
    now: Date.init)
}

/// A main-run-loop timer in the common modes, so it also fires while the user scrolls.
final class RunLoopTimer: MonitorTimer {
  private let timer: Timer

  init(interval: TimeInterval, fire: @escaping () -> Void) {
    timer = Timer(timeInterval: interval, repeats: true) { _ in fire() }
    timer.tolerance = interval / 10
    RunLoop.main.add(timer, forMode: .common)
  }

  deinit {
    cancel()
  }

  func cancel() {
    timer.invalidate()
  }
}

/// Schedules integrity passes and reports only new, changed, or cleared findings.
///
/// Passes run on the main thread: `start`, `resume`, and `manual` run the full `snapshot()` set;
/// `interval` runs the runtime tier (instrumentation and debugger) while the app is active; a
/// matching dyld image load runs instrumentation only. Each pass diffs only the types it covers.
final class IntegrityMonitor {
  typealias Detect = (
    _ types: Set<HardeningSignalType>, _ loads: (_ listed: [String]) -> [ImageLoad]
  ) -> [HardeningSignal]

  static let fullTier = Set(MobileHardeningKit.detectionOrder)
  static let runtimeTier: Set<HardeningSignalType> = [.instrumentation, .debuggerAttach]
  static let imageLoadTier: Set<HardeningSignalType> = [.instrumentation]

  /// Findings are equal when their type, techniques, and artifacts match; timestamps and other
  /// metadata are ignored.
  private struct Finding {
    let techniques: [String]
    let artifacts: [String]
    let metadata: [String: Any]

    init(_ metadata: [String: Any]) {
      techniques = (metadata["techniques"] as? [String] ?? []).sorted()
      artifacts = (metadata["artifacts"] as? [String] ?? []).sorted()
      self.metadata = metadata
    }

    func sameKey(as other: Finding) -> Bool {
      techniques == other.techniques && artifacts == other.artifacts
    }
  }

  private let config: IntegrityMonitorConfig
  private let probe: HardeningProbe
  private let environment: MonitorEnvironment
  private let detect: Detect
  private let handler: (HardeningSignal) -> Void
  private var running = false
  private var findings: [HardeningSignalType: Finding] = [:]
  private var loads: [ImageLoad] = []
  private var observers: [NSObjectProtocol] = []
  private var timer: MonitorTimer?
  private var imageObservation: ImageLoadObservation?

  init(
    config: IntegrityMonitorConfig, probe: HardeningProbe, environment: MonitorEnvironment,
    detect: @escaping Detect, handler: @escaping (HardeningSignal) -> Void
  ) {
    self.config = config
    self.probe = probe
    self.environment = environment
    self.detect = detect
    self.handler = handler
  }

  deinit {
    stop()
  }

  func start() {
    guard !running else { return }
    running = true
    let center = environment.notificationCenter
    for name in [
      UIApplication.willResignActiveNotification, UIApplication.didEnterBackgroundNotification,
    ] {
      observers.append(
        center.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
          self?.pause()
        })
    }
    observers.append(
      center.addObserver(
        forName: UIApplication.didBecomeActiveNotification, object: nil, queue: .main
      ) { [weak self] _ in
        self?.resume()
      })
    imageObservation = probe.observeImageLoads { [weak self] loads in
      self?.imageLoadsObserved(loads)
    }
    runPass(.start, Self.fullTier)
    if running, probe.isApplicationActive { startTimer() }
  }

  /// Ends monitoring and forgets every finding. Safe to call repeatedly.
  func stop() {
    running = false
    observers.forEach(environment.notificationCenter.removeObserver)
    observers.removeAll()
    timer?.cancel()
    timer = nil
    imageObservation?.cancel()
    imageObservation = nil
    findings.removeAll()
    loads.removeAll()
  }

  func checkNow() {
    runPass(.manual, Self.fullTier)
  }

  private func pause() {
    timer?.cancel()
    timer = nil
  }

  private func resume() {
    if config.checkOnResume { runPass(.resume, Self.fullTier) }
    if running { startTimer() }
  }

  private func startTimer() {
    timer?.cancel()
    timer = environment.scheduleRepeating(config.effectiveInterval) { [weak self] in
      self?.runPass(.interval, Self.runtimeTier)
    }
  }

  /// Replayed images (all `live == false`) belong to the start pass; any live load is an
  /// `imageLoad` pass.
  private func imageLoadsObserved(_ newLoads: [ImageLoad]) {
    let trigger: IntegrityTrigger = newLoads.contains(where: \.live) ? .imageLoad : .start
    runPass(trigger, Self.imageLoadTier, newLoads: newLoads)
  }

  private func runPass(
    _ trigger: IntegrityTrigger, _ types: Set<HardeningSignalType>, newLoads: [ImageLoad] = []
  ) {
    guard running else { return }
    let signals = detect(types) { listed in mergeLoads(listed: listed, newLoads: newLoads) }
    var events: [HardeningSignal] = []
    var present: Set<HardeningSignalType> = []
    for signal in signals {
      present.insert(signal.type)
      let finding = Finding(signal.metadata)
      let previous = findings.updateValue(finding, forKey: signal.type)
      if let previous, previous.sameKey(as: finding) { continue }
      events.append(
        event(signal.type, signal.metadata, previous == nil ? .detected : .changed, trigger))
    }
    for type in MobileHardeningKit.detectionOrder
    where types.contains(type) && !present.contains(type) {
      guard let previous = findings.removeValue(forKey: type) else { continue }
      events.append(event(type, previous.metadata, .cleared, trigger))
    }
    for event in events {
      // The handler may stop or restart monitoring; later events of this pass are then stale.
      guard running else { return }
      handler(event)
    }
  }

  /// Keeps observed loads only while their image is still listed, so a `dyldImageLoad` finding
  /// stays stable across later passes and clears when the image is gone.
  private func mergeLoads(listed: [String], newLoads: [ImageLoad]) -> [ImageLoad] {
    let listedPaths = Set(listed)
    var merged = loads.filter { listedPaths.contains($0.path) }
    for load in newLoads {
      if let index = merged.firstIndex(where: { $0.path == load.path }) {
        merged[index] = ImageLoad(path: load.path, live: merged[index].live || load.live)
      } else {
        merged.append(load)
      }
    }
    loads = merged
    return merged
  }

  private func event(
    _ type: HardeningSignalType, _ metadata: [String: Any], _ change: IntegrityChange,
    _ trigger: IntegrityTrigger
  ) -> HardeningSignal {
    var metadata = metadata
    metadata["change"] = change.rawValue
    metadata["trigger"] = trigger.rawValue
    return HardeningSignal(type: type, observedAt: environment.now(), metadata: metadata)
  }
}
