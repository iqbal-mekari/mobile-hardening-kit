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

}
