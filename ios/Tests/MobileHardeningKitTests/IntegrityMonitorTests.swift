import UIKit
import XCTest

@testable import MobileHardeningKit

final class IntegrityMonitorConfigTests: XCTestCase {
  func testDefaultsMatchTheContract() {
    let config = IntegrityMonitorConfig()
    XCTAssertEqual(config.interval, 30)
    XCTAssertTrue(config.checkOnResume)
    XCTAssertEqual(config.effectiveInterval, 30)
  }

  func testIntervalIsClampedToTheSupportedRange() {
    XCTAssertEqual(IntegrityMonitorConfig(interval: 86_400).effectiveInterval, 86_400)
    XCTAssertEqual(IntegrityMonitorConfig(interval: 86_401).effectiveInterval, 86_400)
    XCTAssertEqual(IntegrityMonitorConfig(interval: .infinity).effectiveInterval, 86_400)
    XCTAssertEqual(IntegrityMonitorConfig(interval: -.infinity).effectiveInterval, 5)
    XCTAssertEqual(IntegrityMonitorConfig(interval: 1e12).effectiveInterval, 86_400)

    XCTAssertEqual(IntegrityMonitorConfig(interval: 1).effectiveInterval, 5)
    XCTAssertEqual(IntegrityMonitorConfig(interval: -3).effectiveInterval, 5)
    XCTAssertEqual(IntegrityMonitorConfig(interval: .nan).effectiveInterval, 5)
    XCTAssertEqual(IntegrityMonitorConfig(interval: 5).effectiveInterval, 5)
    XCTAssertEqual(IntegrityMonitorConfig(interval: 90).effectiveInterval, 90)
  }
}

final class IntegrityMonitorTests: XCTestCase {
  private let gadget = "fridagadget.dylib"
  private var probe: FakeProbe!
  private var fake: FakeMonitorEnvironment!
  private var kit: MobileHardeningKit!
  private var received: [HardeningSignal] = []

  override func setUp() {
    super.setUp()
    probe = FakeProbe()
    fake = FakeMonitorEnvironment()
    kit = MobileHardeningKit(
      probe: probe, secureContainer: FakeSecureContainer(),
      monitorEnvironment: fake.environment)
    received = []
  }

  override func tearDown() {
    kit = nil
    super.tearDown()
  }

  private func start(_ config: IntegrityMonitorConfig = .init()) {
    kit.startMonitoring(config) { [unowned self] in received.append($0) }
  }

  /// Events since the last call, without the simulator's constant `emulator` finding.
  private func take() -> [HardeningSignal] {
    defer { received.removeAll() }
    return received.filter { $0.type != .emulator }
  }

  private func post(_ name: Notification.Name) {
    fake.notificationCenter.post(name: name, object: nil)
    pumpMainQueue()
  }

  private func summary(_ events: [HardeningSignal]) -> [String] {
    events.map {
      "\($0.type.rawValue):\($0.metadata["change"] ?? "-"):\($0.metadata["trigger"] ?? "-")"
    }
  }

  // MARK: passes and diffing

  func testFirstPassReportsEveryFindingAsDetected() {
    probe.existingPaths = ["/var/jb"]
    probe.imageNames = ["/private/var/containers/" + gadget]
    probe.debuggerAttached = true
    probe.codeSignature = false
    start()

    let events = received
    XCTAssertEqual(
      summary(events),
      [
        "jailbreak:detected:start", "instrumentation:detected:start",
        "debuggerAttach:detected:start", "emulator:detected:start",
        "signatureMismatch:detected:start",
      ].filter { $0.hasPrefix("emulator") ? isSimulator : true })
    let instrumentation = events.first { $0.type == .instrumentation }
    XCTAssertEqual(instrumentation?.metadata["artifacts"] as? [String], [gadget])
    XCTAssertEqual(instrumentation?.metadata["techniques"] as? [String], ["dyldImage"])
    XCTAssertEqual(instrumentation?.observedAt, fake.now)
    let debugger = events.first { $0.type == .debuggerAttach }
    XCTAssertEqual(debugger?.metadata["techniques"] as? [String], ["pTraced"])
    XCTAssertEqual(debugger?.metadata["traced"] as? Bool, true)
  }

  private var isSimulator: Bool {
    #if targetEnvironment(simulator)
      return true
    #else
      return false
    #endif
  }

  func testScreenAndDisplayTypesStayOffTheIntegrityStream() {
    probe.capture.captured = true
    probe.screenCount = 2
    probe.imageNames = ["/private/var/containers/" + gadget]
    start()
    XCTAssertEqual(summary(take()), ["instrumentation:detected:start"])

    probe.capture.captured = false
    probe.screenCount = 1
    kit.checkIntegrityNow()
    XCTAssertTrue(received.isEmpty, "\(summary(received))")
    XCTAssertFalse(IntegrityMonitor.fullTier.contains(.screenCaptureActive))
    XCTAssertFalse(IntegrityMonitor.fullTier.contains(.externalDisplay))
  }

  func testUnchangedPassesStaySilent() {
    probe.imageNames = ["/private/var/containers/" + gadget]
    start()
    XCTAssertEqual(summary(take()), ["instrumentation:detected:start"])

    fake.fireTimer()
    kit.checkIntegrityNow()
    post(UIApplication.didBecomeActiveNotification)

    XCTAssertTrue(received.isEmpty, "\(summary(received))")
  }

  func testChangedArtifactsAndTechniquesAreReportedAsChanged() {
    probe.imageNames = ["/private/var/containers/" + gadget]
    start()
    _ = take()

    probe.imageNames = ["/private/var/containers/" + gadget, "/usr/lib/libhooker.dylib"]
    fake.fireTimer()
    let changed = take()
    XCTAssertEqual(summary(changed), ["instrumentation:changed:interval"])
    XCTAssertEqual(
      changed.first?.metadata["artifacts"] as? [String], [gadget, "libhooker.dylib"])

    // Same artifacts in a different order are the same finding.
    probe.imageNames = ["/usr/lib/libhooker.dylib", "/private/var/containers/" + gadget]
    fake.fireTimer()
    XCTAssertTrue(take().isEmpty)
  }

  func testClearedFindingsCarryTheLastMetadata() {
    probe.debuggerAttached = true
    probe.imageNames = ["/private/var/containers/" + gadget]
    start()
    _ = take()

    probe.debuggerAttached = false
    probe.imageNames = []
    fake.now = fake.now.addingTimeInterval(30)
    fake.fireTimer()

    let cleared = take()
    XCTAssertEqual(
      summary(cleared), ["instrumentation:cleared:interval", "debuggerAttach:cleared:interval"])
    XCTAssertEqual(cleared[0].metadata["artifacts"] as? [String], [gadget])
    XCTAssertEqual(cleared[1].metadata["techniques"] as? [String], ["pTraced"])
    XCTAssertEqual(cleared[1].observedAt, fake.now)

    probe.debuggerAttached = true
    fake.fireTimer()
    XCTAssertEqual(summary(take()), ["debuggerAttach:detected:interval"])
  }

  func testIntervalPassesRunOnlyTheRuntimeTierAndNeverClearOtherTypes() {
    probe.existingPaths = ["/var/jb"]
    start()
    XCTAssertEqual(summary(take()), ["jailbreak:detected:start"])

    probe.existingPaths = []
    probe.codeSignature = false
    probe.screenCount = 2
    probe.debuggerAttached = true
    fake.fireTimer()
    XCTAssertEqual(summary(take()), ["debuggerAttach:detected:interval"])

    kit.checkIntegrityNow()
    XCTAssertEqual(
      summary(take()),
      ["signatureMismatch:detected:manual", "jailbreak:cleared:manual"])
  }

  func testTheIntervalIsClampedAndUsesTheConfiguredValue() {
    start(IntegrityMonitorConfig(interval: 1))
    XCTAssertEqual(fake.activeTimers.map(\.interval), [5])

    start(IntegrityMonitorConfig(interval: 45))
    XCTAssertEqual(fake.activeTimers.map(\.interval), [45])
  }

  // MARK: lifecycle

  func testIntervalPausesWhileInactiveAndResumesWithAFullPass() {
    probe.imageNames = ["/private/var/containers/" + gadget]
    start()
    _ = take()

    post(UIApplication.willResignActiveNotification)
    XCTAssertTrue(fake.activeTimers.isEmpty)
    post(UIApplication.didEnterBackgroundNotification)
    XCTAssertTrue(fake.activeTimers.isEmpty)

    probe.existingPaths = ["/var/jb"]
    probe.imageNames = []
    post(UIApplication.didBecomeActiveNotification)

    XCTAssertEqual(
      summary(take()), ["jailbreak:detected:resume", "instrumentation:cleared:resume"])
    XCTAssertEqual(fake.activeTimers.count, 1)
  }

  func testResumeWithoutCheckOnResumeOnlyRestartsTheInterval() {
    start(IntegrityMonitorConfig(checkOnResume: false))
    _ = take()
    post(UIApplication.willResignActiveNotification)

    probe.debuggerAttached = true
    post(UIApplication.didBecomeActiveNotification)
    XCTAssertTrue(take().isEmpty)

    fake.fireTimer()
    XCTAssertEqual(summary(take()), ["debuggerAttach:detected:interval"])
  }

  func testRepeatedBecomeActiveKeepsASingleTimer() {
    start()
    post(UIApplication.didBecomeActiveNotification)
    post(UIApplication.didBecomeActiveNotification)
    XCTAssertEqual(fake.activeTimers.count, 1)
  }

  func testStartingWhileInactiveWaitsForBecomeActiveBeforePolling() {
    probe.applicationActive = false
    start()
    XCTAssertTrue(fake.activeTimers.isEmpty)

    post(UIApplication.didBecomeActiveNotification)
    XCTAssertEqual(fake.activeTimers.count, 1)
  }

  func testRestartReplacesTheSessionAndReportsAgain() {
    probe.imageNames = ["/private/var/containers/" + gadget]
    var first: [HardeningSignal] = []
    kit.startMonitoring { first.append($0) }
    start()

    XCTAssertEqual(first.filter { $0.type != .emulator }.count, 1)
    XCTAssertEqual(summary(take()), ["instrumentation:detected:start"])
    XCTAssertEqual(fake.activeTimers.count, 1)
    XCTAssertEqual(probe.imageLoads.activeObservations, 1)

    post(UIApplication.didBecomeActiveNotification)
    XCTAssertEqual(first.filter { $0.type != .emulator }.count, 1, "old handler is detached")
  }

  func testStopEndsEverythingAndIsSafeWhenIdle() {
    kit.stopMonitoring()
    kit.checkIntegrityNow()
    XCTAssertTrue(received.isEmpty)

    start()
    _ = take()
    kit.stopMonitoring()
    kit.stopMonitoring()

    XCTAssertTrue(fake.activeTimers.isEmpty)
    XCTAssertEqual(probe.imageLoads.activeObservations, 0)
    probe.debuggerAttached = true
    kit.checkIntegrityNow()
    post(UIApplication.didBecomeActiveNotification)
    for timer in fake.timers { timer.fire() }
    XCTAssertTrue(received.isEmpty)
  }

  func testDeallocatingTheKitStopsMonitoring() {
    start()
    kit = nil

    XCTAssertTrue(fake.activeTimers.isEmpty)
    XCTAssertEqual(probe.imageLoads.activeObservations, 0)
    for timer in fake.timers { timer.fire() }
    XCTAssertTrue(take().isEmpty)
  }

  func testStartingARunningMonitorIsANoOp() {
    var passes: [Set<HardeningSignalType>] = []
    let monitor = IntegrityMonitor(
      config: .init(), probe: probe, environment: fake.environment,
      detect: { types, _ in
        passes.append(types)
        return [HardeningSignal(type: .debuggerAttach)]
      },
      handler: { [unowned self] in received.append($0) })
    monitor.start()
    monitor.start()

    XCTAssertEqual(passes, [IntegrityMonitor.fullTier])
    XCTAssertEqual(summary(received), ["debuggerAttach:detected:start"])
    XCTAssertEqual(fake.activeTimers.count, 1)
  }

  func testHandlerCanStopMonitoringMidPass() {
    probe.existingPaths = ["/var/jb"]
    probe.debuggerAttached = true
    kit.startMonitoring { [unowned self] signal in
      received.append(signal)
      kit.stopMonitoring()
    }
    XCTAssertEqual(received.count, 1)
    XCTAssertTrue(fake.activeTimers.isEmpty)
  }

  func testMonitoringIsIndependentOfScreenEvents() {
    start()
    XCTAssertEqual(probe.capture.activeObservations, 0)

    kit.startObserving { _ in }
    kit.stopObserving()
    XCTAssertEqual(fake.activeTimers.count, 1)
    XCTAssertEqual(probe.imageLoads.activeObservations, 1)
  }

  func testEventsAreDeliveredOnTheMainThreadWithTheSharedSchema() {
    probe.debuggerAttached = true
    var threads: [Bool] = []
    kit.startMonitoring { signal in
      threads.append(Thread.isMainThread)
      XCTAssertEqual(Set(signal.dictionary.keys), ["type", "observedAt", "metadata"])
    }
    XCTAssertFalse(threads.isEmpty)
    XCTAssertTrue(threads.allSatisfy { $0 })
  }

  // MARK: image loads

  func testALiveImageLoadRunsAnInstrumentationOnlyPass() {
    start()
    _ = take()

    probe.existingPaths = ["/var/jb"]
    probe.debuggerAttached = true
    probe.imageNames = ["/private/var/containers/" + gadget]
    probe.imageLoads.deliver([ImageLoad(path: gadget, live: true)])

    let events = take()
    XCTAssertEqual(summary(events), ["instrumentation:detected:imageLoad"])
    XCTAssertEqual(events.first?.metadata["artifacts"] as? [String], [gadget])
    XCTAssertEqual(
      events.first?.metadata["techniques"] as? [String], ["dyldImage", "dyldImageLoad"])

    // The load stays attributed while the image is listed, so later passes stay silent.
    fake.fireTimer()
    XCTAssertEqual(summary(take()), ["debuggerAttach:detected:interval"])
    kit.checkIntegrityNow()
    XCTAssertEqual(summary(take()), ["jailbreak:detected:manual"])

    probe.imageNames = []
    fake.fireTimer()
    XCTAssertEqual(summary(take()), ["instrumentation:cleared:interval"])
    fake.fireTimer()
    XCTAssertTrue(take().isEmpty)
  }

  func testAnImageThatUnloadsBeforeThePassIsStillReportedOnce() {
    start()
    probe.imageLoads.deliver([ImageLoad(path: gadget, live: true)])
    let events = take()
    XCTAssertEqual(summary(events), ["instrumentation:detected:imageLoad"])
    XCTAssertEqual(events.first?.metadata["techniques"] as? [String], ["dyldImageLoad"])

    fake.fireTimer()
    XCTAssertEqual(summary(take()), ["instrumentation:cleared:interval"])
  }

  func testReplayedImagesBelongToTheStartPass() {
    probe.imageNames = ["/private/var/containers/" + gadget]
    start()
    _ = take()

    probe.imageLoads.deliver([ImageLoad(path: gadget, live: false)])
    XCTAssertTrue(take().isEmpty, "replay of an already reported image is not a new finding")

    let unloaded = "ellekit.dylib"
    probe.imageLoads.deliver([ImageLoad(path: unloaded, live: false)])
    let events = take()
    XCTAssertEqual(summary(events), ["instrumentation:changed:start"])
    XCTAssertEqual(events.first?.metadata["artifacts"] as? [String], [gadget, unloaded])
    XCTAssertEqual(events.first?.metadata["techniques"] as? [String], ["dyldImage"])
  }

  func testALiveLoadOfAReplayedImageAddsTheLoadTechnique() {
    probe.imageNames = ["/private/var/containers/" + gadget]
    start()
    probe.imageLoads.deliver([ImageLoad(path: gadget, live: false)])
    _ = take()

    probe.imageLoads.deliver([
      ImageLoad(path: gadget, live: true), ImageLoad(path: gadget, live: false),
    ])
    let events = take()
    XCTAssertEqual(summary(events), ["instrumentation:changed:imageLoad"])
    XCTAssertEqual(
      events.first?.metadata["techniques"] as? [String], ["dyldImage", "dyldImageLoad"])
  }
}
