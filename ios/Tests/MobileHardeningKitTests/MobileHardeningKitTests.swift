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

final class MobileHardeningKitTests: XCTestCase {
  private var kit: MobileHardeningKit!

  override func setUp() {
    super.setUp()
    kit = MobileHardeningKit()
  }

  override func tearDown() {
    kit.setScreenProtectionEnabled(false)
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

  func testObservingReportsScreenshotAndCaptureChanges() {
    var received: [HardeningSignal] = []
    kit.startObserving { received.append($0) }

    NotificationCenter.default.post(
      name: UIApplication.userDidTakeScreenshotNotification, object: nil)
    NotificationCenter.default.post(name: UIScreen.capturedDidChangeNotification, object: nil)
    pumpMainQueue()

    let screenshot = received.first { $0.type == .screenshotTaken }
    XCTAssertEqual(screenshot?.metadata["active"] as? Bool, true)
    let capture = received.first { $0.type == .screenCaptureActive }
    XCTAssertEqual(capture?.metadata["active"] as? Bool, UIScreen.main.isCaptured)
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

  // MARK: screen protection

  private func obscuringViews(in window: UIWindow) -> [UIView] {
    window.subviews.filter {
      $0.accessibilityIdentifier == MobileHardeningKit.obscuringViewIdentifier
    }
  }

  private func protectedKit(window: UIWindow?, applicationActive: Bool = true)
    -> MobileHardeningKit
  {
    MobileHardeningKit(probe: FakeProbe(window: window, applicationActive: applicationActive))
  }

  private func post(_ name: Notification.Name) {
    NotificationCenter.default.post(name: name, object: nil)
    pumpMainQueue()
  }

  func testProtectionBlursOnResignAndClearsOnBecomeActive() {
    let window = UIWindow(frame: UIScreen.main.bounds)
    let kit = protectedKit(window: window)
    kit.setScreenProtectionEnabled(true)

    post(UIApplication.willResignActiveNotification)
    XCTAssertEqual(obscuringViews(in: window).count, 1)

    // A second resign must not stack overlays.
    post(UIApplication.willResignActiveNotification)
    XCTAssertEqual(obscuringViews(in: window).count, 1)

    post(UIApplication.didBecomeActiveNotification)
    XCTAssertTrue(obscuringViews(in: window).isEmpty)
  }

  func testEnablingWhileInactiveObscuresImmediately() {
    let window = UIWindow(frame: UIScreen.main.bounds)
    let kit = protectedKit(window: window, applicationActive: false)

    kit.setScreenProtectionEnabled(true)

    XCTAssertEqual(obscuringViews(in: window).count, 1)
  }

  func testDisablingProtectionRemovesAnActiveOverlayAndStopsObserving() {
    let window = UIWindow(frame: UIScreen.main.bounds)
    let kit = protectedKit(window: window)
    kit.setScreenProtectionEnabled(true)
    kit.setScreenProtectionEnabled(true)  // idempotent: no duplicate observers
    post(UIApplication.willResignActiveNotification)
    XCTAssertEqual(obscuringViews(in: window).count, 1)

    kit.setScreenProtectionEnabled(false)
    XCTAssertTrue(obscuringViews(in: window).isEmpty)

    post(UIApplication.willResignActiveNotification)
    XCTAssertTrue(obscuringViews(in: window).isEmpty, "disabled protection must not blur")
  }

  func testProtectionIsIndependentOfEventObservation() {
    let window = UIWindow(frame: UIScreen.main.bounds)
    let kit = protectedKit(window: window)
    kit.setScreenProtectionEnabled(true)  // no startObserving

    post(UIApplication.willResignActiveNotification)

    XCTAssertEqual(obscuringViews(in: window).count, 1)
  }

  func testNothingIsObscuredWithoutOptIn() {
    let window = UIWindow(frame: UIScreen.main.bounds)
    _ = protectedKit(window: window)

    post(UIApplication.willResignActiveNotification)

    XCTAssertTrue(obscuringViews(in: window).isEmpty)
  }

  func testMissingKeyWindowIsHandledGracefully() {
    let kit = protectedKit(window: nil)
    kit.setScreenProtectionEnabled(true)

    post(UIApplication.willResignActiveNotification)
    post(UIApplication.didBecomeActiveNotification)
  }
}

// MARK: - Detector logic with an injected environment

private struct FakeProbe: HardeningProbe {
  var existingPaths: Set<String> = []
  var openableSchemes: Set<String> = []
  var imageNames: [String] = []
  var debuggerAttached = false
  var captured = false
  var screenCount = 1
  var codeSignature = true
  var window: UIWindow?
  var applicationActive = true

  func fileExists(atPath path: String) -> Bool { existingPaths.contains(path) }
  func canOpen(scheme: String) -> Bool { openableSchemes.contains(scheme) }
  func loadedImageNames() -> [String] { imageNames }
  func isDebuggerAttached() -> Bool { debuggerAttached }
  func isScreenCaptured() -> Bool { captured }
  func hasCodeSignature() -> Bool { codeSignature }
  func keyWindow() -> UIWindow? { window }
  var isApplicationActive: Bool { applicationActive }
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
    let signals = snapshot(FakeProbe(debuggerAttached: true, captured: true, screenCount: 3))

    XCTAssertEqual(
      signals.map(\.type), [.debuggerAttach, .screenCaptureActive, .externalDisplay])
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
    let kit = MobileHardeningKit(probe: FakeProbe(captured: true, screenCount: 2))
    var received: [HardeningSignal] = []
    kit.startObserving { received.append($0) }
    defer { kit.stopObserving() }

    NotificationCenter.default.post(name: UIScreen.capturedDidChangeNotification, object: nil)
    NotificationCenter.default.post(name: UIScreen.didConnectNotification, object: nil)
    let drained = expectation(description: "main queue drained")
    DispatchQueue.main.async { drained.fulfill() }
    wait(for: [drained], timeout: 2)

    XCTAssertEqual(
      received.first { $0.type == .screenCaptureActive }?.metadata["active"] as? Bool, true)
    let display = received.first { $0.type == .externalDisplay }
    XCTAssertEqual(display?.metadata["connected"] as? Bool, true)
    XCTAssertEqual(display?.metadata["displayCount"] as? Int, 1)
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
