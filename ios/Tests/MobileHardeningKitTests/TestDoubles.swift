import UIKit
import XCTest

@testable import MobileHardeningKit

final class FakeCapture {
  var captured: Bool
  private var handlers: [ObjectIdentifier: () -> Void] = [:]
  var activeObservations: Int { handlers.count }

  init(captured: Bool = false) {
    self.captured = captured
  }

  func observe(_ onChange: @escaping () -> Void) -> CaptureObservation {
    let observation = Observation(owner: self)
    handlers[ObjectIdentifier(observation)] = onChange
    return observation
  }

  func change(to captured: Bool) {
    self.captured = captured
    for handler in handlers.values { handler() }
  }

  private final class Observation: CaptureObservation {
    weak var owner: FakeCapture?
    init(owner: FakeCapture) { self.owner = owner }
    func cancel() { owner?.handlers[ObjectIdentifier(self)] = nil }
  }
}

/// Drives `observeImageLoads` deterministically.
final class FakeImageLoads {
  private var handlers: [ObjectIdentifier: ([ImageLoad]) -> Void] = [:]
  var activeObservations: Int { handlers.count }

  func observe(_ onLoad: @escaping ([ImageLoad]) -> Void) -> ImageLoadObservation {
    let observation = Observation(owner: self)
    handlers[ObjectIdentifier(observation)] = onLoad
    return observation
  }

  func deliver(_ loads: [ImageLoad]) {
    for handler in handlers.values { handler(loads) }
  }

  private final class Observation: ImageLoadObservation {
    weak var owner: FakeImageLoads?
    init(owner: FakeImageLoads) { self.owner = owner }
    func cancel() { owner?.handlers[ObjectIdentifier(self)] = nil }
  }
}

final class FakeProbe: HardeningProbe {
  var existingPaths: Set<String>
  var openableSchemes: Set<String>
  var imageNames: [String]
  var debuggerAttached: Bool
  var capture: FakeCapture
  let imageLoads = FakeImageLoads()
  var screenCount: Int
  var codeSignature: Bool
  var window: UIWindow?
  var applicationActive = true
  var isiOSAppOnMac = false
  let captureSource = "fakeSource"

  init(
    existingPaths: Set<String> = [], openableSchemes: Set<String> = [], imageNames: [String] = [],
    debuggerAttached: Bool = false, capture: FakeCapture = FakeCapture(), screenCount: Int = 1,
    codeSignature: Bool = true, window: UIWindow? = nil
  ) {
    self.existingPaths = existingPaths
    self.openableSchemes = openableSchemes
    self.imageNames = imageNames
    self.debuggerAttached = debuggerAttached
    self.capture = capture
    self.screenCount = screenCount
    self.codeSignature = codeSignature
    self.window = window
  }

  func fileExists(atPath path: String) -> Bool { existingPaths.contains(path) }
  func canOpen(scheme: String) -> Bool { openableSchemes.contains(scheme) }
  func forEachLoadedImage(_ body: (UnsafePointer<CChar>) -> Void) {
    for name in imageNames { name.withCString(body) }
  }
  func observeImageLoads(_ onLoad: @escaping ([ImageLoad]) -> Void) -> ImageLoadObservation {
    imageLoads.observe(onLoad)
  }
  func isDebuggerAttached() -> Bool { debuggerAttached }
  func isScreenCaptured() -> Bool { capture.captured }
  func observeCaptureChanges(_ onChange: @escaping () -> Void) -> CaptureObservation {
    capture.observe(onChange)
  }
  func hasCodeSignature() -> Bool { codeSignature }
  func keyWindow() -> UIWindow? { window }
  var isApplicationActive: Bool { applicationActive }
}

final class FakeSecureContainer: SecureCaptureContainer {
  var result = SecureCaptureAttachResult.attached
  private(set) var attachedWindow: UIWindow?
  private(set) var secure = false
  private(set) var attachCount = 0

  func attach(to window: UIWindow) -> SecureCaptureAttachResult {
    attachCount += 1
    if result == .attached { attachedWindow = window }
    return result
  }

  func setSecure(_ secure: Bool) { self.secure = secure }

  func detach() {
    attachedWindow = nil
    secure = false
  }
}

/// Manually fired repeating timers and a settable clock for the monitor.
final class FakeMonitorEnvironment {
  final class Timer: MonitorTimer {
    let interval: TimeInterval
    let fire: () -> Void
    private(set) var cancelled = false

    init(interval: TimeInterval, fire: @escaping () -> Void) {
      self.interval = interval
      self.fire = fire
    }

    func cancel() { cancelled = true }
  }

  let notificationCenter = NotificationCenter()
  var now = Date(timeIntervalSince1970: 1_767_323_045)
  private(set) var timers: [Timer] = []

  var activeTimers: [Timer] { timers.filter { !$0.cancelled } }

  var environment: MonitorEnvironment {
    MonitorEnvironment(
      scheduleRepeating: { [unowned self] interval, fire in
        let timer = Timer(interval: interval, fire: fire)
        timers.append(timer)
        return timer
      },
      notificationCenter: notificationCenter,
      now: { [unowned self] in now })
  }

  /// Fires the single active timer once.
  func fireTimer(file: StaticString = #filePath, line: UInt = #line) {
    XCTAssertEqual(activeTimers.count, 1, "active timers", file: file, line: line)
    activeTimers.first?.fire()
  }
}

extension XCTestCase {
  func pumpMainQueue() {
    let done = expectation(description: "main queue drained")
    DispatchQueue.main.async { done.fulfill() }
    wait(for: [done], timeout: 2)
  }
}
