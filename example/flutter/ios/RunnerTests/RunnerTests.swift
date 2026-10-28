import Flutter
import UIKit
import XCTest

@testable import mobile_hardening_kit

final class RunnerTests: XCTestCase {
  private var plugin: MobileHardeningKitPlugin!
  private var testWindow: UIWindow?

  override func setUp() {
    super.setUp()
    plugin = MobileHardeningKitPlugin()
  }

  override func tearDown() {
    _ = call("setScreenProtection", [:])
    testWindow?.isHidden = true
    testWindow = nil
    plugin = nil
    super.tearDown()
  }

  func testSimulatorSnapshotIncludesSimulatorSignal() throws {
    #if targetEnvironment(simulator)
      let plugin = MobileHardeningKitPlugin()
      var response: Any?
      plugin.handle(FlutterMethodCall(methodName: "snapshot", arguments: [:])) { value in
        response = value
      }
      let signals = try XCTUnwrap(response as? [[String: Any]])
      let emulator = try XCTUnwrap(signals.first { $0["type"] as? String == "emulator" })
      let types = signals.compactMap { $0["type"] as? String }
      XCTAssertEqual(Set(types).count, types.count)
      for signal in signals {
        XCTAssertNil(signal["confidence"])
      }
      XCTAssertEqual((emulator["metadata"] as? [String: String])?["environment"], "simulator")
    #else
      throw XCTSkip("Simulator signal is only emitted by simulator builds.")
    #endif
  }

  // MARK: screen protection

  private func call(_ method: String, _ arguments: Any?) -> Any? {
    var response: Any?
    plugin.handle(FlutterMethodCall(methodName: method, arguments: arguments)) { response = $0 }
    return response
  }

  private func setProtection(_ arguments: Any?) throws -> [String: Any] {
    try XCTUnwrap(call("setScreenProtection", arguments) as? [String: Any])
  }

  /// A key window in the host app's window scene, as the scene-based key-window lookup sees it.
  private func makeKeyWindow() throws -> UIWindow {
    let scene = try XCTUnwrap(
      UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }.first)
    let window = UIWindow(windowScene: scene)
    window.frame = scene.coordinateSpace.bounds
    window.makeKeyAndVisible()
    testWindow = window
    return window
  }

  private func overlays(in window: UIWindow, _ identifier: String) -> [UIView] {
    window.subviews.filter { $0.accessibilityIdentifier == identifier }
  }

  func testAppSwitcherProtectionDoesNotRequireEventSubscription() throws {
    let window = try makeKeyWindow()

    let state = try setProtection(["obscureAppSwitcher": true])

    XCTAssertEqual(state["obscuresAppSwitcher"] as? Bool, true)
    NotificationCenter.default.post(name: UIApplication.willResignActiveNotification, object: nil)
    XCTAssertEqual(overlays(in: window, MobileHardeningKit.obscuringViewIdentifier).count, 1)
    NotificationCenter.default.post(name: UIApplication.didBecomeActiveNotification, object: nil)
    XCTAssertTrue(overlays(in: window, MobileHardeningKit.obscuringViewIdentifier).isEmpty)
  }

  func testSetScreenProtectionReturnsTheAppliedStateMap() throws {
    let state = try setProtection([
      "blockCapture": false, "obscureWhileCaptured": true, "obscureAppSwitcher": false,
    ])

    XCTAssertEqual(
      Set(state.keys),
      ["captureBlocked", "obscuresWhileCaptured", "obscuresAppSwitcher", "unavailable"])
    XCTAssertEqual(state["captureBlocked"] as? Bool, false)
    XCTAssertEqual(state["obscuresWhileCaptured"] as? Bool, true)
    XCTAssertEqual(state["obscuresAppSwitcher"] as? Bool, false)
    XCTAssertEqual(state["unavailable"] as? [String], [])
  }

  func testMissingArgumentsRequestNoProtection() throws {
    let window = try makeKeyWindow()

    let state = try setProtection(nil)

    XCTAssertEqual(state["captureBlocked"] as? Bool, false)
    XCTAssertEqual(state["obscuresWhileCaptured"] as? Bool, false)
    XCTAssertEqual(state["obscuresAppSwitcher"] as? Bool, false)
    NotificationCenter.default.post(name: UIApplication.willResignActiveNotification, object: nil)
    XCTAssertTrue(overlays(in: window, MobileHardeningKit.obscuringViewIdentifier).isEmpty)
  }

  func testBlockCaptureReparentsTheKeyWindowAndOffRestoresIt() throws {
    let window = try makeKeyWindow()
    let originalSuperlayer = try XCTUnwrap(window.layer.superlayer)
    let originalIndex = originalSuperlayer.sublayers?.firstIndex(of: window.layer)

    let state = try setProtection(["blockCapture": true])

    // The simulator exposes the secure-entry sublayer, so the best-effort technique applies here;
    // failure reasons are covered by the core tests through the injectable container.
    XCTAssertEqual(state["captureBlocked"] as? Bool, true)
    XCTAssertEqual(state["unavailable"] as? [String], [])
    let secureLayer = try XCTUnwrap(window.layer.superlayer)
    XCTAssertFalse(secureLayer === originalSuperlayer)
    let field = try XCTUnwrap(secureLayer.superlayer?.delegate as? UITextField)
    XCTAssertTrue(field.isSecureTextEntry)
    XCTAssertTrue(secureLayer.superlayer?.superlayer === originalSuperlayer)

    XCTAssertEqual(try setProtection(["blockCapture": false])["captureBlocked"] as? Bool, false)
    XCTAssertTrue(window.layer.superlayer === originalSuperlayer)
    XCTAssertEqual(originalSuperlayer.sublayers?.firstIndex(of: window.layer), originalIndex)
  }

  func testTheRemovedBooleanMethodIsNotImplemented() {
    let response = call("setScreenProtectionEnabled", ["enabled": true])

    XCTAssertTrue((response as AnyObject) === FlutterMethodNotImplemented)
  }

  func testSnapshotReturnsSchemaMaps() throws {
    let plugin = MobileHardeningKitPlugin()
    var response: Any?
    plugin.handle(FlutterMethodCall(methodName: "snapshot", arguments: nil)) { response = $0 }

    let signals = try XCTUnwrap(response as? [[String: Any]])
    for signal in signals {
      XCTAssertEqual(Set(signal.keys), ["type", "observedAt", "metadata"])
      XCTAssertTrue(signal["type"] is String)
      XCTAssertNotNil(
        ISO8601DateFormatter().date(from: try XCTUnwrap(signal["observedAt"] as? String)))
      XCTAssertTrue(signal["metadata"] is [String: Any])
    }
  }

  func testUnknownMethodIsNotImplemented() {
    let plugin = MobileHardeningKitPlugin()
    var response: Any?
    plugin.handle(FlutterMethodCall(methodName: "unknown", arguments: nil)) { response = $0 }

    XCTAssertTrue((response as AnyObject) === FlutterMethodNotImplemented)
  }

  func testEventStreamForwardsSignalMapsUntilCancelled() throws {
    let plugin = MobileHardeningKitPlugin()
    var events: [[String: Any]] = []
    XCTAssertNil(
      plugin.onListen(withArguments: nil) { event in
        if let map = event as? [String: Any] { events.append(map) }
      })

    NotificationCenter.default.post(
      name: UIApplication.userDidTakeScreenshotNotification, object: nil)
    let delivered = expectation(description: "event delivered")
    DispatchQueue.main.async { delivered.fulfill() }
    wait(for: [delivered], timeout: 2)
    XCTAssertEqual(events.first?["type"] as? String, "screenshotTaken")

    XCTAssertNil(plugin.onCancel(withArguments: nil))
    let count = events.count
    NotificationCenter.default.post(
      name: UIApplication.userDidTakeScreenshotNotification, object: nil)
    let drained = expectation(description: "queue drained")
    DispatchQueue.main.async { drained.fulfill() }
    wait(for: [drained], timeout: 2)
    XCTAssertEqual(events.count, count)
  }
}
