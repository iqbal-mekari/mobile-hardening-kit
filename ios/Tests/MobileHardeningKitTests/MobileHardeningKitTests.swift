import UIKit
import XCTest

@testable import MobileHardeningKit

final class HardeningSignalTests: XCTestCase {
  func testDictionaryUsesSharedSchemaWithUtcIsoTimestamp() throws {
    let observedAt = Date(timeIntervalSince1970: 1_767_323_045)
    let signal = HardeningSignal(
      type: .externalDisplay, observedAt: observedAt, metadata: ["displayCount": 1])

    let dictionary = signal.dictionary

    XCTAssertEqual(Set(dictionary.keys), ["type", "observedAt", "metadata"])
    XCTAssertEqual(dictionary["type"] as? String, "externalDisplay")
    XCTAssertEqual(dictionary["observedAt"] as? String, "2026-01-02T03:04:05Z")
    XCTAssertEqual((dictionary["metadata"] as? [String: Int])?["displayCount"], 1)
  }

  func testMetadataDefaultsToEmpty() {
    XCTAssertTrue(HardeningSignal(type: .root).metadata.isEmpty)
  }

  func testTypeRawValuesMatchTheDartEnumNames() {
    let expected = [
      "root", "jailbreak", "instrumentation", "debuggerAttach", "signatureMismatch", "emulator",
      "accessibilityUnrecognized", "devModeEnabled", "screenCaptureActive", "screenshotTaken",
      "externalDisplay",
    ]
    for name in expected {
      XCTAssertEqual(HardeningSignalType(rawValue: name)?.rawValue, name)
    }
    XCTAssertNil(HardeningSignalType(rawValue: "unknown"))
  }
}

final class ScreenProtectionModelTests: XCTestCase {
  func testOffRequestsNothing() {
    XCTAssertEqual(ScreenProtection.off, ScreenProtection())
    XCTAssertFalse(ScreenProtection.off.blockCapture)
    XCTAssertFalse(ScreenProtection.off.obscureWhileCaptured)
    XCTAssertFalse(ScreenProtection.off.obscureAppSwitcher)
    XCTAssertNotEqual(ScreenProtection.off, ScreenProtection(obscureAppSwitcher: true))
  }

  func testStateMapUsesTheChannelContractKeys() {
    let state = ScreenProtectionState(
      captureBlocked: false, obscuresWhileCaptured: true, obscuresAppSwitcher: true,
      unavailable: ["blockCapture:windowNotReady"])

    let map = state.toMap()

    XCTAssertEqual(
      Set(map.keys),
      ["captureBlocked", "obscuresWhileCaptured", "obscuresAppSwitcher", "unavailable"])
    XCTAssertEqual(map["captureBlocked"] as? Bool, false)
    XCTAssertEqual(map["obscuresWhileCaptured"] as? Bool, true)
    XCTAssertEqual(map["obscuresAppSwitcher"] as? Bool, true)
    XCTAssertEqual(map["unavailable"] as? [String], ["blockCapture:windowNotReady"])
  }

  func testOffStateAppliesNothing() {
    XCTAssertEqual(
      ScreenProtectionState.off,
      ScreenProtectionState(
        captureBlocked: false, obscuresWhileCaptured: false, obscuresAppSwitcher: false,
        unavailable: []))
  }
}

final class MobileHardeningKitTests: XCTestCase {
  private var kit: MobileHardeningKit!

  override func setUp() {
    super.setUp()
    kit = MobileHardeningKit()
  }

  override func tearDown() {
    kit.setScreenProtection(.off)
    kit.stopObserving()
    kit = nil
    super.tearDown()
  }

  private func pumpMainQueue() {
    let done = expectation(description: "main queue drained")
    DispatchQueue.main.async { done.fulfill() }
    wait(for: [done], timeout: 2)
  }

  // MARK: snapshot

  func testSnapshotHasAtMostOneSignalPerTypeAndReportsSimulator() throws {
    let signals = kit.snapshot()
    let types = signals.map(\.type)
    XCTAssertEqual(Set(types).count, types.count)
    #if targetEnvironment(simulator)
      let emulator = try XCTUnwrap(signals.first { $0.type == .emulator })
      XCTAssertEqual(emulator.metadata["environment"] as? String, "simulator")
    #endif
    for signal in signals {
      XCTAssertEqual(
        Set(signal.dictionary.keys), ["type", "observedAt", "metadata"])
    }
  }

  func testSnapshotOmitsAndroidOnlySignals() {
    let androidOnly: Set<HardeningSignalType> = [
      .root, .accessibilityUnrecognized, .devModeEnabled,
    ]
    XCTAssertTrue(Set(kit.snapshot().map(\.type)).isDisjoint(with: androidOnly))
  }

  func testSignatureFindingIsOnlyAboutAMissingCodeSignature() {
    if let signal = kit.snapshot().first(where: { $0.type == .signatureMismatch }) {
      XCTAssertEqual(signal.metadata["codeSignaturePresent"] as? Bool, false)
    }
  }

  func testJailbreakFindingIsBounded() {
    guard let signal = kit.snapshot().first(where: { $0.type == .jailbreak }) else { return }
    XCTAssertLessThanOrEqual((signal.metadata["artifacts"] as? [String])?.count ?? 0, 8)
    XCTAssertNotNil(signal.metadata["urlSchemes"] as? [String])
  }

  // MARK: events

  func testObservingReportsScreenshots() {
    var received: [HardeningSignal] = []
    kit.startObserving { received.append($0) }

    NotificationCenter.default.post(
      name: UIApplication.userDidTakeScreenshotNotification, object: nil)
    pumpMainQueue()

    let screenshot = received.first { $0.type == .screenshotTaken }
    XCTAssertEqual(screenshot?.metadata["active"] as? Bool, true)
  }

  func testObservingReportsExternalDisplayConnectionChanges() {
    var received: [HardeningSignal] = []
    kit.startObserving { received.append($0) }

    NotificationCenter.default.post(name: UIScreen.didConnectNotification, object: nil)
    NotificationCenter.default.post(name: UIScreen.didDisconnectNotification, object: nil)
    pumpMainQueue()

    let displays = received.filter { $0.type == .externalDisplay }
    XCTAssertEqual(displays.count, 2)
    let expectedCount = max(0, UIScreen.screens.count - 1)
    for display in displays {
      XCTAssertEqual(display.metadata["displayCount"] as? Int, expectedCount)
      XCTAssertEqual(display.metadata["connected"] as? Bool, expectedCount > 0)
    }
  }

  func testStopObservingEndsDelivery() {
    var received: [HardeningSignal] = []
    kit.startObserving { received.append($0) }
    kit.stopObserving()

    NotificationCenter.default.post(
      name: UIApplication.userDidTakeScreenshotNotification, object: nil)
    pumpMainQueue()

    XCTAssertTrue(received.isEmpty)
  }

  func testRestartingReplacesTheHandlerWithoutDuplicateDelivery() {
    var first: [HardeningSignal] = []
    var second: [HardeningSignal] = []
    kit.startObserving { first.append($0) }
    kit.startObserving { second.append($0) }

    NotificationCenter.default.post(
      name: UIApplication.userDidTakeScreenshotNotification, object: nil)
    pumpMainQueue()

    XCTAssertTrue(first.isEmpty)
    XCTAssertEqual(second.count, 1)
  }

  func testDeallocatingStopsObservation() {
    var received: [HardeningSignal] = []
    var scoped: MobileHardeningKit? = MobileHardeningKit()
    scoped?.startObserving { received.append($0) }
    scoped = nil

    NotificationCenter.default.post(
      name: UIApplication.userDidTakeScreenshotNotification, object: nil)
    pumpMainQueue()

    XCTAssertTrue(received.isEmpty)
  }

  func testSystemProtectionRoundTripLeavesNothingBehind() {
    let state = kit.setScreenProtection(
      ScreenProtection(blockCapture: true, obscureWhileCaptured: true, obscureAppSwitcher: true))
    XCTAssertTrue(state.obscuresWhileCaptured)
    XCTAssertTrue(state.obscuresAppSwitcher)
    XCTAssertEqual(state.captureBlocked, state.unavailable.isEmpty)

    XCTAssertEqual(kit.setScreenProtection(.off), .off)
    XCTAssertEqual(kit.screenProtectionState, .off)
  }
}

// MARK: - Screen protection with an injected environment

final class ScreenProtectionTests: XCTestCase {
  private var probe: FakeProbe!
  private var container: FakeSecureContainer!
  private var window: UIWindow!

  override func setUp() {
    super.setUp()
    window = UIWindow(frame: CGRect(x: 0, y: 0, width: 320, height: 640))
    probe = FakeProbe(window: window)
    container = FakeSecureContainer()
  }

  private func makeKit() -> MobileHardeningKit {
    MobileHardeningKit(probe: probe, secureContainer: container)
  }

  private func post(_ name: Notification.Name) {
    NotificationCenter.default.post(name: name, object: nil)
    let done = expectation(description: "main queue drained")
    DispatchQueue.main.async { done.fulfill() }
    wait(for: [done], timeout: 2)
  }

  private func views(_ identifier: String) -> [UIView] {
    window.subviews.filter { $0.accessibilityIdentifier == identifier }
  }

  private var obscuringViews: [UIView] { views(MobileHardeningKit.obscuringViewIdentifier) }
  private var captureCovers: [UIView] { views(MobileHardeningKit.captureCoverViewIdentifier) }

  // MARK: obscureAppSwitcher

  func testAppSwitcherBlursOnResignAndClearsOnBecomeActive() {
    let kit = makeKit()
    let state = kit.setScreenProtection(ScreenProtection(obscureAppSwitcher: true))
    XCTAssertEqual(
      state,
      ScreenProtectionState(
        captureBlocked: false, obscuresWhileCaptured: false, obscuresAppSwitcher: true,
        unavailable: []))

    post(UIApplication.willResignActiveNotification)
    XCTAssertEqual(obscuringViews.count, 1)

    // A second resign must not stack overlays.
    post(UIApplication.willResignActiveNotification)
    XCTAssertEqual(obscuringViews.count, 1)

    post(UIApplication.didBecomeActiveNotification)
    XCTAssertTrue(obscuringViews.isEmpty)
  }

  func testEnablingAppSwitcherWhileInactiveObscuresImmediately() {
    probe.applicationActive = false
    let kit = makeKit()
    kit.setScreenProtection(ScreenProtection(obscureAppSwitcher: true))

    XCTAssertEqual(obscuringViews.count, 1)
  }

  func testTurningProtectionOffRemovesTheBlurAndStopsObserving() {
    let kit = makeKit()
    kit.setScreenProtection(ScreenProtection(obscureAppSwitcher: true))
    kit.setScreenProtection(ScreenProtection(obscureAppSwitcher: true))  // no duplicate observers
    post(UIApplication.willResignActiveNotification)
    XCTAssertEqual(obscuringViews.count, 1)

    kit.setScreenProtection(.off)
    XCTAssertTrue(obscuringViews.isEmpty)

    post(UIApplication.willResignActiveNotification)
    XCTAssertTrue(obscuringViews.isEmpty, "disabled protection must not blur")
  }

  func testDroppingOnlyTheAppSwitcherOptionRemovesTheBlur() {
    let kit = makeKit()
    kit.setScreenProtection(ScreenProtection(obscureWhileCaptured: true, obscureAppSwitcher: true))
    post(UIApplication.willResignActiveNotification)
    XCTAssertEqual(obscuringViews.count, 1)

    kit.setScreenProtection(ScreenProtection(obscureWhileCaptured: true))
    XCTAssertTrue(obscuringViews.isEmpty)
    post(UIApplication.willResignActiveNotification)
    XCTAssertTrue(obscuringViews.isEmpty)
  }

  func testNothingIsObscuredWithoutOptIn() {
    probe.capture.captured = true
    let kit = makeKit()

    post(UIApplication.willResignActiveNotification)

    XCTAssertTrue(obscuringViews.isEmpty)
    XCTAssertTrue(captureCovers.isEmpty)
    XCTAssertEqual(container.attachCount, 0)
    XCTAssertEqual(kit.screenProtectionState, .off)
  }

  func testMissingKeyWindowIsHandledGracefully() {
    probe.window = nil
    probe.capture.captured = true
    let kit = makeKit()
    let state = kit.setScreenProtection(
      ScreenProtection(obscureWhileCaptured: true, obscureAppSwitcher: true))

    post(UIApplication.willResignActiveNotification)
    post(UIApplication.didBecomeActiveNotification)
    XCTAssertTrue(state.obscuresWhileCaptured)
    XCTAssertTrue(state.unavailable.isEmpty)
  }

  // MARK: obscureWhileCaptured

  func testCaptureCoverFollowsCaptureState() {
    let kit = makeKit()
    let state = kit.setScreenProtection(ScreenProtection(obscureWhileCaptured: true))
    XCTAssertTrue(state.obscuresWhileCaptured)
    XCTAssertTrue(captureCovers.isEmpty)

    probe.capture.change(to: true)
    let cover = captureCovers.first
    XCTAssertEqual(captureCovers.count, 1)
    XCTAssertEqual(cover?.frame, window.bounds)
    XCTAssertEqual(cover?.backgroundColor, .black)
    XCTAssertTrue(window.subviews.last === cover, "cover must be on top")

    probe.capture.change(to: true)  // repeated change must not stack covers
    XCTAssertEqual(captureCovers.count, 1)

    probe.capture.change(to: false)
    XCTAssertTrue(captureCovers.isEmpty)
  }

  func testEnablingWhileCapturedCoversImmediatelyAndOffRemovesIt() {
    probe.capture.captured = true
    let kit = makeKit()
    kit.setScreenProtection(ScreenProtection(obscureWhileCaptured: true))
    XCTAssertEqual(captureCovers.count, 1)

    kit.setScreenProtection(.off)
    XCTAssertTrue(captureCovers.isEmpty)
    XCTAssertEqual(probe.capture.activeObservations, 0)
  }

  func testCaptureStartedWhileInactiveIsCoveredOnBecomeActive() {
    let kit = makeKit()
    kit.setScreenProtection(ScreenProtection(obscureWhileCaptured: true))
    probe.capture.captured = true  // no change callback, e.g. missed while suspended

    post(UIApplication.didBecomeActiveNotification)

    XCTAssertEqual(captureCovers.count, 1)
  }

  func testCaptureCoverAndEventsShareOneRegistration() {
    let kit = makeKit()
    var received: [HardeningSignal] = []
    kit.startObserving { received.append($0) }
    kit.setScreenProtection(ScreenProtection(obscureWhileCaptured: true))
    XCTAssertEqual(probe.capture.activeObservations, 1)

    probe.capture.change(to: true)
    XCTAssertEqual(received.count, 1)
    XCTAssertEqual(captureCovers.count, 1)

    kit.stopObserving()
    XCTAssertEqual(probe.capture.activeObservations, 1, "the cover still needs capture changes")
    kit.setScreenProtection(.off)
    XCTAssertEqual(probe.capture.activeObservations, 0)
  }

  // MARK: blockCapture

  func testBlockCaptureHostsTheKeyWindowSecurely() {
    let kit = makeKit()
    let state = kit.setScreenProtection(ScreenProtection(blockCapture: true))

    XCTAssertEqual(
      state,
      ScreenProtectionState(
        captureBlocked: true, obscuresWhileCaptured: false, obscuresAppSwitcher: false,
        unavailable: []))
    XCTAssertTrue(container.attachedWindow === window)
    XCTAssertTrue(container.secure)
    XCTAssertEqual(kit.screenProtectionState, state)
  }

  func testBlockCaptureIsSkippedOnAMacHost() {
    probe.isiOSAppOnMac = true
    let kit = makeKit()
    let state = kit.setScreenProtection(ScreenProtection(blockCapture: true))

    XCTAssertFalse(state.captureBlocked)
    XCTAssertEqual(state.unavailable, ["blockCapture:iosAppOnMac"])
    XCTAssertEqual(container.attachCount, 0)
  }

  func testBlockCaptureReportsContainerFailures() {
    let kit = makeKit()
    container.result = .secureLayerUnavailable
    XCTAssertEqual(
      kit.setScreenProtection(ScreenProtection(blockCapture: true)).unavailable,
      ["blockCapture:secureLayerUnavailable"])

    // Not a transient failure: becoming active does not retry it.
    post(UIApplication.didBecomeActiveNotification)
    XCTAssertEqual(container.attachCount, 1)
  }

  func testBlockCaptureWithoutAWindowRetriesWhenTheAppBecomesActive() {
    probe.window = nil
    let kit = makeKit()
    let state = kit.setScreenProtection(
      ScreenProtection(blockCapture: true, obscureAppSwitcher: true))
    XCTAssertFalse(state.captureBlocked)
    XCTAssertEqual(state.unavailable, ["blockCapture:noWindow"])

    probe.window = window
    post(UIApplication.didBecomeActiveNotification)

    XCTAssertTrue(kit.screenProtectionState.captureBlocked)
    XCTAssertTrue(kit.screenProtectionState.unavailable.isEmpty)
    XCTAssertTrue(container.attachedWindow === window)
  }

  func testBlockCaptureRetriesAWindowThatIsNotReady() {
    container.result = .windowNotReady
    let kit = makeKit()
    XCTAssertEqual(
      kit.setScreenProtection(ScreenProtection(blockCapture: true)).unavailable,
      ["blockCapture:windowNotReady"])

    post(UIApplication.didBecomeActiveNotification)
    XCTAssertEqual(kit.screenProtectionState.unavailable, ["blockCapture:windowNotReady"])

    container.result = .attached
    post(UIApplication.didBecomeActiveNotification)
    XCTAssertTrue(kit.screenProtectionState.captureBlocked)
  }

  func testBlockCaptureKeepsTheAttachedWindowWhenNoWindowIsKey() {
    let kit = makeKit()
    kit.setScreenProtection(ScreenProtection(blockCapture: true))
    probe.window = nil

    let state = kit.setScreenProtection(ScreenProtection(blockCapture: true))

    XCTAssertTrue(state.captureBlocked)
    XCTAssertTrue(container.attachedWindow === window)
  }

  func testDisablingBlockCaptureDetaches() {
    let kit = makeKit()
    kit.setScreenProtection(ScreenProtection(blockCapture: true))

    let state = kit.setScreenProtection(ScreenProtection(obscureAppSwitcher: true))

    XCTAssertFalse(state.captureBlocked)
    XCTAssertNil(container.attachedWindow)
  }

  func testDeallocatingTheKitRestoresEverything() {
    probe.capture.captured = true
    probe.applicationActive = false
    var kit: MobileHardeningKit? = makeKit()
    kit?.startObserving { _ in }
    kit?.setScreenProtection(
      ScreenProtection(blockCapture: true, obscureWhileCaptured: true, obscureAppSwitcher: true))
    XCTAssertEqual(captureCovers.count, 1)
    XCTAssertEqual(obscuringViews.count, 1)

    kit = nil

    XCTAssertNil(container.attachedWindow)
    XCTAssertTrue(captureCovers.isEmpty)
    XCTAssertTrue(obscuringViews.isEmpty)
    XCTAssertEqual(probe.capture.activeObservations, 0)
  }
}

// MARK: - Detector logic with an injected environment

private final class FakeCapture {
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

private final class FakeProbe: HardeningProbe {
  var existingPaths: Set<String>
  var openableSchemes: Set<String>
  var imageNames: [String]
  var debuggerAttached: Bool
  var capture: FakeCapture
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
  func loadedImageNames() -> [String] { imageNames }
  func isDebuggerAttached() -> Bool { debuggerAttached }
  func isScreenCaptured() -> Bool { capture.captured }
  func observeCaptureChanges(_ onChange: @escaping () -> Void) -> CaptureObservation {
    capture.observe(onChange)
  }
  func hasCodeSignature() -> Bool { codeSignature }
  func keyWindow() -> UIWindow? { window }
  var isApplicationActive: Bool { applicationActive }
}

private final class FakeSecureContainer: SecureCaptureContainer {
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

final class DetectorLogicTests: XCTestCase {
  private func snapshot(_ probe: FakeProbe) -> [HardeningSignal] {
    MobileHardeningKit(probe: probe).snapshot().filter { $0.type != .emulator }
  }

  func testCleanEnvironmentReportsNothing() {
    XCTAssertTrue(snapshot(FakeProbe()).isEmpty)
  }

  func testJailbreakReportsKnownPathsAndSchemesBounded() {
    let paths = [
      "/Applications/Cydia.app", "/Applications/Sileo.app", "/Applications/Zebra.app",
      "/Library/MobileSubstrate/MobileSubstrate.dylib", "/usr/libexec/ssh-keysign",
      "/usr/bin/ssh", "/etc/apt", "/private/var/lib/apt/", "/var/jb",
    ]
    let signal = snapshot(FakeProbe(existingPaths: Set(paths), openableSchemes: ["cydia://"]))
      .first { $0.type == .jailbreak }

    XCTAssertEqual((signal?.metadata["artifacts"] as? [String])?.count, 8)
    XCTAssertEqual(signal?.metadata["urlSchemes"] as? [String], ["cydia://"])
  }

  func testJailbreakFromASchemeAloneIsReported() {
    let signal = snapshot(FakeProbe(openableSchemes: ["sileo://"])).first {
      $0.type == .jailbreak
    }
    XCTAssertEqual(signal?.metadata["artifacts"] as? [String], [])
    XCTAssertEqual(signal?.metadata["urlSchemes"] as? [String], ["sileo://"])
  }

  func testInstrumentationMatchesLoadedImagesCaseInsensitivelyAndBoundsOutput() {
    let long = "/private/var/" + String(repeating: "x", count: 200) + "/FridaGadget.dylib"
    let names =
      [long, "/usr/lib/SUBSTRATE.dylib", "/usr/lib/libSystem.dylib"]
      + (0..<10).map { "/usr/lib/ellekit\($0).dylib" }
    let signal = snapshot(FakeProbe(imageNames: names)).first { $0.type == .instrumentation }

    let artifacts = signal?.metadata["artifacts"] as? [String]
    XCTAssertEqual(artifacts?.count, 8)
    XCTAssertEqual(artifacts?.first?.count, 120)
    XCTAssertTrue(artifacts?.first?.hasSuffix("/fridagadget.dylib") ?? false)
    XCTAssertFalse(artifacts?.contains { $0.contains("libsystem") } ?? true)
  }

  func testCleanImageListIsNotInstrumentation() {
    XCTAssertTrue(snapshot(FakeProbe(imageNames: ["/usr/lib/libSystem.dylib"])).isEmpty)
  }

  func testDebuggerCaptureAndExternalDisplayAreReported() {
    let signals = snapshot(
      FakeProbe(debuggerAttached: true, capture: FakeCapture(captured: true), screenCount: 3))

    XCTAssertEqual(
      signals.map(\.type), [.debuggerAttach, .screenCaptureActive, .externalDisplay])
    XCTAssertEqual(signals[1].metadata["captured"] as? Bool, true)
    XCTAssertEqual(signals[1].metadata["source"] as? String, "fakeSource")
    XCTAssertEqual(signals[2].metadata["displayCount"] as? Int, 2)
  }

  func testSingleScreenIsNotAnExternalDisplay() {
    XCTAssertFalse(snapshot(FakeProbe(screenCount: 1)).contains { $0.type == .externalDisplay })
  }

  func testMissingCodeSignatureIsReported() {
    let signal = snapshot(FakeProbe(codeSignature: false)).first { $0.type == .signatureMismatch }
    XCTAssertEqual(signal?.metadata["codeSignaturePresent"] as? Bool, false)
  }

  func testEventsReadCaptureAndDisplayStateFromTheProbe() {
    let probe = FakeProbe(screenCount: 2)
    let kit = MobileHardeningKit(probe: probe)
    var received: [HardeningSignal] = []
    kit.startObserving { received.append($0) }
    defer { kit.stopObserving() }

    probe.capture.change(to: true)
    NotificationCenter.default.post(name: UIScreen.didConnectNotification, object: nil)
    let drained = expectation(description: "main queue drained")
    DispatchQueue.main.async { drained.fulfill() }
    wait(for: [drained], timeout: 2)

    let capture = received.first { $0.type == .screenCaptureActive }
    XCTAssertEqual(capture?.metadata["active"] as? Bool, true)
    XCTAssertEqual(capture?.metadata["source"] as? String, "fakeSource")
    let display = received.first { $0.type == .externalDisplay }
    XCTAssertEqual(display?.metadata["connected"] as? Bool, true)
    XCTAssertEqual(display?.metadata["displayCount"] as? Int, 1)
  }

  func testStoppingObservationCancelsTheCaptureRegistration() {
    let probe = FakeProbe()
    let kit = MobileHardeningKit(probe: probe)
    kit.startObserving { _ in }
    kit.startObserving { _ in }
    XCTAssertEqual(probe.capture.activeObservations, 1)

    kit.stopObserving()

    XCTAssertEqual(probe.capture.activeObservations, 0)
  }
}

// MARK: - Mach-O code-signature parsing

final class CodeSignatureParsingTests: XCTestCase {
  private let magic64: UInt32 = 0xfeed_facf

  private func word(_ value: UInt32) -> [UInt8] {
    withUnsafeBytes(of: value.littleEndian, Array.init)
  }

  /// A 64-bit Mach-O header (32 bytes) followed by `commands` as (cmd, size, payload) triples.
  private func macho(magic: UInt32? = nil, count: UInt32? = nil, commands: [(UInt32, UInt32)])
    -> Data
  {
    var bytes = word(magic ?? magic64) + [UInt8](repeating: 0, count: 12)
    bytes += word(count ?? UInt32(commands.count)) + [UInt8](repeating: 0, count: 12)
    for (command, size) in commands {
      bytes += word(command) + word(size)
      bytes += [UInt8](repeating: 0, count: max(0, Int(size) - 8))
    }
    return Data(bytes)
  }

  func testFindsCodeSignatureAfterOtherCommands() {
    XCTAssertTrue(SystemProbe.containsCodeSignature(macho(commands: [(0x19, 16), (0x1d, 16)])))
  }

  func testReportsAbsenceWhenNoCodeSignatureCommandExists() {
    XCTAssertFalse(SystemProbe.containsCodeSignature(macho(commands: [(0x19, 16), (0x2, 24)])))
  }

  func testRejectsNon64BitLittleEndianBinaries() {
    XCTAssertFalse(
      SystemProbe.containsCodeSignature(macho(magic: 0xcafe_babe, commands: [(0x1d, 16)])))
  }

  func testRejectsTruncatedInput() {
    XCTAssertFalse(SystemProbe.containsCodeSignature(Data([0xcf, 0xfa, 0xed, 0xfe])))
  }

  func testStopsWhenCommandCountExceedsTheAvailableData() {
    XCTAssertFalse(SystemProbe.containsCodeSignature(macho(count: 500, commands: [(0x19, 16)])))
  }

  func testStopsOnMalformedCommandSizes() {
    XCTAssertFalse(SystemProbe.containsCodeSignature(macho(commands: [(0x19, 4), (0x1d, 16)])))
    XCTAssertFalse(
      SystemProbe.containsCodeSignature(macho(commands: [(0x19, 16), (0x1d, 16)]).dropLast(12)))
  }

  func testRealHostBinaryParsesWithoutCrashing() {
    _ = SystemProbe().hasCodeSignature()
  }
}
