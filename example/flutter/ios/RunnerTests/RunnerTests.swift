import Flutter
import UIKit
import XCTest

@testable import mobile_hardening_kit

final class RunnerTests: XCTestCase {
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
  func testScreenProtectionDoesNotRequireEventSubscription() {
    let plugin = MobileHardeningKitPlugin()
    let window = UIWindow(frame: UIScreen.main.bounds)
    window.makeKeyAndVisible()
    defer {
      plugin.handle(
        FlutterMethodCall(methodName: "setScreenProtectionEnabled", arguments: ["enabled": false])
      ) { _ in }
      window.isHidden = true
    }

    plugin.handle(
      FlutterMethodCall(methodName: "setScreenProtectionEnabled", arguments: ["enabled": true])
    ) { _ in }
    NotificationCenter.default.post(name: UIApplication.willResignActiveNotification, object: nil)
    XCTAssertNotNil(
      window.subviews.first {
        $0.accessibilityIdentifier == "mobile_hardening_kit_background_obscuring_view"
      })

    NotificationCenter.default.post(name: UIApplication.didBecomeActiveNotification, object: nil)
    XCTAssertNil(
      window.subviews.first {
        $0.accessibilityIdentifier == "mobile_hardening_kit_background_obscuring_view"
      })
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

  func testMissingEnabledArgumentLeavesProtectionDisabled() {
    let plugin = MobileHardeningKitPlugin()
    let window = UIWindow(frame: UIScreen.main.bounds)
    window.makeKeyAndVisible()
    defer { window.isHidden = true }

    plugin.handle(FlutterMethodCall(methodName: "setScreenProtectionEnabled", arguments: nil)) {
      _ in
    }
    NotificationCenter.default.post(name: UIApplication.willResignActiveNotification, object: nil)

    XCTAssertNil(
      window.subviews.first {
        $0.accessibilityIdentifier == MobileHardeningKit.obscuringViewIdentifier
      })
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
