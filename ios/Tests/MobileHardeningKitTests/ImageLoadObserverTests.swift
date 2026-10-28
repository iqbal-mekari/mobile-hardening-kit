import Darwin
import MachO
import XCTest

@testable import MobileHardeningKit

final class InjectionNeedlesTests: XCTestCase {
  private func matches(_ path: String) -> Bool {
    path.withCString(InjectionNeedles.matches)
  }

  func testMatchesNeedlesCaseInsensitively() {
    XCTAssertTrue(matches("/usr/lib/FRIDA-agent.dylib"))
    XCTAssertTrue(matches("/Frameworks/FridaGadget.dylib"))
    XCTAssertTrue(matches("/Library/MobileSubstrate/MobileSubstrate.dylib"))
    XCTAssertTrue(matches("/usr/lib/CydiaSubstrate.framework/CydiaSubstrate"))
    XCTAssertTrue(matches("/var/jb/usr/lib/libellekit.dylib"))
  }

  func testIgnoresGenericNames() {
    XCTAssertFalse(matches("/usr/lib/libsubstrate_shim.dylib"))
    XCTAssertFalse(matches("/usr/lib/libSystem.B.dylib"))
    XCTAssertFalse(matches(""))
  }

  func testArtifactsAreLowercasedAndBounded() {
    let long = "/A/" + String(repeating: "b", count: 200) + "/Frida.dylib"
    let artifact = InjectionNeedles.artifact(long)
    XCTAssertEqual(artifact.count, 120)
    XCTAssertTrue(artifact.hasSuffix("/frida.dylib"))
  }
}

/// Exercises the real, process-wide dyld registration. It cannot be undone, so these tests only
/// assert properties that hold whichever test registered first.
final class DyldImageLoadObserverTests: XCTestCase {
  private let observer = DyldImageLoadObserver.shared

  func testRegistrationReplaysEveryLoadedImageOnce() throws {
    let observation = SystemProbe().observeImageLoads { _ in }
    defer { observation.cancel() }

    XCTAssertTrue(observer.waitForRegistration(timeout: 10))
    let state = observer.state
    XCTAssertTrue(state.live)
    XCTAssertGreaterThan(state.replayedImages, 0)
    XCTAssertEqual(state.replayedImages, state.imagesAtRegistration)
    XCTAssertLessThanOrEqual(state.replayedImages, Int(_dyld_image_count()))
  }

  func testLaterLoadsReachTheCallbackOnTheLoadingThread() throws {
    let candidates = [
      "/System/Library/Frameworks/CoreNFC.framework/CoreNFC",
      "/System/Library/Frameworks/GameKit.framework/GameKit",
      "/System/Library/Frameworks/HealthKit.framework/HealthKit",
      "/System/Library/Frameworks/WeatherKit.framework/WeatherKit",
      "/usr/lib/libxslt.1.dylib",
    ]
    guard let path = candidates.first(where: { dlopen($0, RTLD_NOLOAD) == nil }) else {
      throw XCTSkip("every candidate system image is already loaded")
    }
    let observation = SystemProbe().observeImageLoads { _ in }
    defer { observation.cancel() }
    XCTAssertTrue(observer.waitForRegistration(timeout: 10))
    XCTAssertTrue(observer.state.enabled)
    let callbacks = observer.state.callbacks

    let handle = dlopen(path, RTLD_NOW)
    XCTAssertNotNil(handle, path)
    defer { handle.map { _ = dlclose($0) } }

    XCTAssertGreaterThan(observer.state.callbacks, callbacks)
  }

  func testMatchingPathsAreCopiedBatchedAndDeliveredOnMain() {
    let delivered = expectation(description: "delivered")
    var batches: [[ImageLoad]] = []
    var onMain = true
    let observation = observer.observe { loads in
      onMain = onMain && Thread.isMainThread
      batches.append(loads)
      if batches.flatMap({ $0 }).count == 2 { delivered.fulfill() }
    }
    defer { observation.cancel() }
    var cancelledCalls = 0
    let cancelled = observer.observe { _ in cancelledCalls += 1 }
    cancelled.cancel()
    cancelled.cancel()

    "/private/var/tmp/FridaGadget.dylib".withCString { observer.imagePathAdded($0, live: true) }
    "/usr/lib/libSystem.B.dylib".withCString { observer.imagePathAdded($0, live: true) }
    "/var/jb/ElleKit.dylib".withCString { observer.imagePathAdded($0, live: false) }
    wait(for: [delivered], timeout: 5)

    XCTAssertTrue(onMain)
    XCTAssertEqual(
      batches.flatMap { $0 },
      [
        ImageLoad(path: "/private/var/tmp/fridagadget.dylib", live: true),
        ImageLoad(path: "/var/jb/ellekit.dylib", live: false),
      ])
    XCTAssertEqual(cancelledCalls, 0)
  }

  func testCallbacksAreDisabledWithoutSubscribers() {
    var observation: ImageLoadObservation? = observer.observe { _ in }
    XCTAssertTrue(observer.state.enabled)
    observation = nil
    XCTAssertNil(observation)
    XCTAssertFalse(observer.state.enabled)
  }

  func testHitsWithoutSubscribersAreDropped() {
    "/tmp/frida.dylib".withCString { observer.imagePathAdded($0, live: true) }
    observer.queue.sync {}  // enqueue ran and scheduled the flush
    observer.queue.sync {}  // flush ran with no subscribers

    let observation = observer.observe { _ in XCTFail("the dropped hit must not be redelivered") }
    defer { observation.cancel() }
    pumpMainQueue()
  }

  func testTheRealKitReportsAnInjectedImageLoad() {
    let kit = MobileHardeningKit()
    defer { kit.stopMonitoring() }
    let loaded = expectation(description: "imageLoad event")
    var events: [HardeningSignal] = []
    kit.startMonitoring { signal in
      events.append(signal)
      if signal.metadata["trigger"] as? String == "imageLoad" { loaded.fulfill() }
    }
    XCTAssertTrue(observer.waitForRegistration(timeout: 10))

    "/private/var/tmp/FridaGadget.dylib".withCString { observer.imagePathAdded($0, live: true) }
    wait(for: [loaded], timeout: 5)

    let load = events.last
    XCTAssertEqual(load?.type, .instrumentation)
    XCTAssertEqual(load?.metadata["change"] as? String, "detected")
    XCTAssertEqual(
      load?.metadata["artifacts"] as? [String], ["/private/var/tmp/fridagadget.dylib"])
    XCTAssertEqual(load?.metadata["techniques"] as? [String], ["dyldImageLoad"])
    kit.checkIntegrityNow()
  }
}

final class RunLoopTimerTests: XCTestCase {
  func testFiresRepeatedlyOnMainUntilCancelled() {
    let fired = expectation(description: "fired twice")
    fired.expectedFulfillmentCount = 2
    var count = 0
    var timer: MonitorTimer?
    timer = MonitorEnvironment.system.scheduleRepeating(0.05) {
      XCTAssertTrue(Thread.isMainThread)
      count += 1
      if count <= 2 { fired.fulfill() }
      if count == 2 { timer?.cancel() }
    }
    wait(for: [fired], timeout: 5)

    let settled = expectation(description: "no more fires")
    DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) { settled.fulfill() }
    wait(for: [settled], timeout: 5)
    XCTAssertEqual(count, 2)
    XCTAssertLessThan(abs(MonitorEnvironment.system.now().timeIntervalSinceNow), 5)
  }
}
