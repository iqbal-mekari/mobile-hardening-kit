import UIKit
import XCTest

@testable import MobileHardeningKit

/// Exercises the real UIKit layer reparenting against a stand-in host layer, so no app window or
/// screen is needed. Capture blanking itself can only be verified on a physical device.
final class SystemSecureCaptureContainerTests: XCTestCase {
  private var host: CALayer!
  private var siblings: [CALayer]!
  private var window: UIWindow!

  override func setUp() {
    super.setUp()
    host = CALayer()
    siblings = [CALayer(), CALayer()]
    window = UIWindow(frame: CGRect(x: 0, y: 0, width: 320, height: 640))
    host.addSublayer(siblings[0])
    host.addSublayer(window.layer)
    host.addSublayer(siblings[1])
  }

  private var originalOrder: [CALayer] { [siblings[0], window.layer, siblings[1]] }

  func testAttachHostsTheWindowInTheFieldsSecureSublayer() throws {
    let container = SystemSecureCaptureContainer()

    XCTAssertEqual(container.attach(to: window), .attached)

    XCTAssertTrue(container.attachedWindow === window)
    let fieldLayer = try XCTUnwrap(host.sublayers?[1])
    XCTAssertEqual(host.sublayers?.count, 3, "the field layer takes the window's place")
    XCTAssertEqual(fieldLayer.frame, .zero)
    XCTAssertTrue(window.layer.superlayer === fieldLayer.sublayers?.last)
    let field = try XCTUnwrap(fieldLayer.delegate as? UITextField)
    XCTAssertTrue(field.isSecureTextEntry)
    XCTAssertNil(field.superview, "the field must not stay in the window it hosts")
    XCTAssertEqual(field.semanticContentAttribute, .forceLeftToRight)
    XCTAssertFalse(field.isUserInteractionEnabled)

    container.setSecure(false)
    XCTAssertFalse(field.isSecureTextEntry)
    container.setSecure(true)
    XCTAssertTrue(field.isSecureTextEntry)
    container.detach()
  }

  func testPreIOS17LayoutUsesTheFirstSublayer() throws {
    let container = SystemSecureCaptureContainer(usesLastSublayer: false)

    XCTAssertEqual(container.attach(to: window), .attached)

    let fieldLayer = try XCTUnwrap(host.sublayers?[1])
    XCTAssertTrue(window.layer.superlayer === fieldLayer.sublayers?.first)
    container.detach()
    XCTAssertEqual(host.sublayers, originalOrder)
  }

  func testSecureSublayerOrderMatchesTheRunningRelease() {
    if #available(iOS 17.0, *) {
      XCTAssertTrue(SystemSecureCaptureContainer.secureSublayerIsLast)
    } else {
      XCTAssertFalse(SystemSecureCaptureContainer.secureSublayerIsLast)
    }
  }

  func testDetachRestoresTheOriginalLayerTree() {
    let container = SystemSecureCaptureContainer()
    XCTAssertEqual(container.attach(to: window), .attached)

    container.detach()
    container.detach()  // idempotent

    XCTAssertEqual(host.sublayers, originalOrder)
    XCTAssertNil(container.attachedWindow)
    XCTAssertTrue(window.subviews.isEmpty)
  }

  func testReattachingTheSameWindowIsANoOp() {
    let container = SystemSecureCaptureContainer()
    XCTAssertEqual(container.attach(to: window), .attached)
    let fieldLayer = host.sublayers?[1]

    XCTAssertEqual(container.attach(to: window), .attached)

    XCTAssertTrue(host.sublayers?[1] === fieldLayer)
    container.detach()
    XCTAssertEqual(host.sublayers, originalOrder)
  }

  func testAttachingAnotherWindowReleasesTheFirst() {
    let container = SystemSecureCaptureContainer()
    let otherHost = CALayer()
    let other = UIWindow(frame: window.frame)
    otherHost.addSublayer(other.layer)
    XCTAssertEqual(container.attach(to: window), .attached)

    XCTAssertEqual(container.attach(to: other), .attached)

    XCTAssertEqual(host.sublayers, originalOrder)
    XCTAssertTrue(container.attachedWindow === other)
    container.detach()
    XCTAssertEqual(otherHost.sublayers, [other.layer])
  }

  func testWindowWithoutASuperlayerIsNotReady() {
    let container = SystemSecureCaptureContainer()
    let detached = UIWindow(frame: window.frame)
    detached.layer.removeFromSuperlayer()

    XCTAssertEqual(container.attach(to: detached), .windowNotReady)

    XCTAssertNil(container.attachedWindow)
    XCTAssertTrue(detached.subviews.isEmpty)
  }

  func testMissingSecureSublayerLeavesTheTreeUntouched() {
    let container = SystemSecureCaptureContainer(makeField: { LayerlessTextField() })

    XCTAssertEqual(container.attach(to: window), .secureLayerUnavailable)

    XCTAssertEqual(host.sublayers, originalOrder)
    XCTAssertNil(container.attachedWindow)
    XCTAssertTrue(window.subviews.isEmpty)
    container.setSecure(true)  // no field: harmless
  }

  func testDetachAfterTheHostLayerIsGoneOrphansTheWindowLayer() {
    let container = SystemSecureCaptureContainer()
    autoreleasepool {
      CATransaction.begin()
      let transientHost = CALayer()
      transientHost.addSublayer(window.layer)
      XCTAssertEqual(container.attach(to: window), .attached)
      CATransaction.commit()
    }
    CATransaction.flush()

    container.detach()

    XCTAssertNil(window.layer.superlayer)
  }

  func testDeinitRestoresTheOriginalLayerTree() {
    var container: SystemSecureCaptureContainer? = SystemSecureCaptureContainer()
    XCTAssertEqual(container?.attach(to: window), .attached)

    container = nil

    XCTAssertEqual(host.sublayers, originalOrder)
  }
}

/// A text field that never exposes sublayers, as on an iOS release that changed its structure.
private final class LayerlessTextField: UITextField {
  override func layoutSubviews() {
    super.layoutSubviews()
    for sublayer in layer.sublayers ?? [] { sublayer.removeFromSuperlayer() }
  }
}

final class SystemProbeSceneTests: XCTestCase {
  func testSceneAwareReadsAreConsistentOnTheSimulator() {
    let probe = SystemProbe()
    XCTAssertFalse(probe.isiOSAppOnMac)
    if #available(iOS 17.0, *) {
      XCTAssertEqual(probe.captureSource, "sceneCaptureState")
    } else {
      XCTAssertEqual(probe.captureSource, "screenIsCaptured")
    }
    XCTAssertFalse(probe.isScreenCaptured())
    if let window = probe.keyWindow() {
      XCTAssertTrue(window.isKeyWindow)
    }
  }

  func testSystemCaptureObservationCanBeCancelledRepeatedly() {
    let observation = SystemProbe().observeCaptureChanges {}
    if #available(iOS 17.0, *) {
      XCTAssertTrue(observation is SceneCaptureStateObservation)
    } else {
      XCTAssertTrue(observation is ScreenCapturedObservation)
    }
    observation.cancel()
    observation.cancel()
  }

  func testLegacyObservationFollowsTheScreenNotificationUntilCancelled() {
    var changes = 0
    let observation = ScreenCapturedObservation { changes += 1 }

    NotificationCenter.default.post(name: UIScreen.capturedDidChangeNotification, object: nil)
    XCTAssertEqual(changes, 1)

    observation.cancel()
    NotificationCenter.default.post(name: UIScreen.capturedDidChangeNotification, object: nil)
    XCTAssertEqual(changes, 1)
  }

  @available(iOS 17.0, *)
  func testSceneObservationIgnoresNonWindowSceneConnections() {
    var changes = 0
    let observation = SceneCaptureStateObservation { changes += 1 }
    defer { observation.cancel() }

    NotificationCenter.default.post(name: UIScene.willConnectNotification, object: nil)

    XCTAssertEqual(changes, 0)
  }

  @available(iOS 17.0, *)
  func testSceneObservationFollowsTheCaptureTraitUntilCancelled() {
    var changes = 0
    let observation = SceneCaptureStateObservation { changes += 1 }
    let window = UIWindow(frame: CGRect(x: 0, y: 0, width: 10, height: 10))
    let view = UIView()
    window.addSubview(view)
    observation.register(view)
    observation.register(view)  // registered once

    view.traitOverrides.sceneCaptureState = .active
    view.updateTraitsIfNeeded()
    XCTAssertEqual(changes, 1)

    observation.cancel()
    view.traitOverrides.sceneCaptureState = .inactive
    view.updateTraitsIfNeeded()
    XCTAssertEqual(changes, 1)
  }
}
