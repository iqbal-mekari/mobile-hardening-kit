import Darwin
import Foundation
import MachO
import UIKit

/// Client-side integrity and display observations. Reports only; never blocks a flow.
/// Signals are heuristic and are not a security boundary. Call from the main thread.
///
/// `startObserving`/`stopObserving` control event delivery; screen protection is opt-in
/// and independent of event observation.
public final class MobileHardeningKit {
  private let probe: HardeningProbe
  private let secureContainer: SecureCaptureContainer
  private var handler: ((HardeningSignal) -> Void)?
  private var streamObservers: [NSObjectProtocol] = []
  private var protectionObservers: [NSObjectProtocol] = []
  private var captureObservation: CaptureObservation?
  private var protection = ScreenProtection.off
  private var blockCaptureFailure: String?
  private var obscuringView: UIView?
  private var captureCoverView: UIView?

  /// `blockCapture` failures that can resolve once a window is on screen.
  private static let retriedBlockCaptureFailures: Set = [
    "noWindow", SecureCaptureAttachResult.windowNotReady.rawValue,
  ]

  /// Accessibility identifier of the app-switcher blur overlay.
  public static let obscuringViewIdentifier = "mobile_hardening_kit_background_obscuring_view"

  /// Accessibility identifier of the opaque cover shown while the screen is captured.
  public static let captureCoverViewIdentifier = "mobile_hardening_kit_capture_cover_view"

  /// Protection applied by the latest `setScreenProtection(_:)` call, updated when a deferred
  /// `blockCapture` attach succeeds after the app becomes active.
  public private(set) var screenProtectionState = ScreenProtectionState.off

  public convenience init() {
    self.init(probe: SystemProbe())
  }

  init(
    probe: HardeningProbe,
    secureContainer: SecureCaptureContainer = SystemSecureCaptureContainer()
  ) {
    self.probe = probe
    self.secureContainer = secureContainer
  }

  deinit {
    stopObserving()
    setScreenProtection(.off)
  }

  /// Returns observations in detection order, at most one per type. Unsupported checks are omitted.
  public func snapshot() -> [HardeningSignal] {
    var signals: [HardeningSignal] = []
    func add(_ type: HardeningSignalType, _ metadata: [String: Any] = [:]) {
      signals.append(HardeningSignal(type: type, metadata: metadata))
    }

    let jailbreakPaths = [
      "/Applications/Cydia.app", "/Applications/Sileo.app", "/Applications/Zebra.app",
      "/Library/MobileSubstrate/MobileSubstrate.dylib", "/usr/libexec/ssh-keysign",
      "/usr/bin/ssh", "/etc/apt", "/private/var/lib/apt/", "/var/jb",
    ].filter(probe.fileExists(atPath:))
    let suspiciousSchemes = ["cydia://", "sileo://"].filter(probe.canOpen(scheme:))
    if !jailbreakPaths.isEmpty || !suspiciousSchemes.isEmpty {
      add(
        .jailbreak,
        ["artifacts": Array(jailbreakPaths.prefix(8)), "urlSchemes": suspiciousSchemes])
    }

    let injectionNames = ["frida", "substrate", "substitute", "libhooker", "ellekit", "xposed"]
    let injectedLibraries = probe.loadedImageNames()
      .map { $0.lowercased() }
      .filter { name in injectionNames.contains(where: name.contains) }
      .map { String($0.suffix(120)) }
    if !injectedLibraries.isEmpty {
      add(.instrumentation, ["artifacts": Array(injectedLibraries.prefix(8))])
    }

    if probe.isDebuggerAttached() {
      add(.debuggerAttach, ["traced": true])
    }

    #if targetEnvironment(simulator)
      add(.emulator, ["environment": "simulator"])
    #endif

    if probe.isScreenCaptured() {
      add(.screenCaptureActive, ["captured": true, "source": probe.captureSource])
    }
    if probe.screenCount > 1 {
      add(.externalDisplay, ["displayCount": probe.screenCount - 1])
    }

    // iOS does not expose its app-signing certificate fingerprint to sandboxed
    // applications. Report only if the signed main executable lacks a code signature.
    if !probe.hasCodeSignature() {
      add(.signatureMismatch, ["codeSignaturePresent": false])
    }
    return signals
  }

  /// Applies `protection` and reports what was actually applied. Options not requested are
  /// removed; `.off` restores the window exactly as it was.
  ///
  /// `blockCapture` is best-effort and **not supported by Apple**: it uses undocumented UIKit
  /// behaviour (see `ScreenProtection`) and may stop working in any iOS release. When it cannot be
  /// applied, `unavailable` names the reason; `noWindow` and `windowNotReady` are retried each time
  /// the app becomes active, and `screenProtectionState` reflects the retry.
  @discardableResult
  public func setScreenProtection(_ protection: ScreenProtection) -> ScreenProtectionState {
    self.protection = protection
    applyBlockCapture()
    updateProtectionObservers()
    updateCaptureObservation()
    updateCaptureCover()
    if !protection.obscureAppSwitcher {
      removeObscuringView()
    } else if !probe.isApplicationActive {
      showObscuringView()
    }
    return publishState()
  }

  /// Starts delivering capture, screenshot, and external-display changes to `handler`.
  public func startObserving(_ handler: @escaping (HardeningSignal) -> Void) {
    stopObserving()
    self.handler = handler
    let center = NotificationCenter.default
    streamObservers.append(
      center.addObserver(
        forName: UIApplication.userDidTakeScreenshotNotification, object: nil, queue: .main
      ) { [weak self] _ in
        self?.handler?(HardeningSignal(type: .screenshotTaken, metadata: ["active": true]))
      })
    streamObservers.append(
      center.addObserver(forName: UIScreen.didConnectNotification, object: nil, queue: .main) {
        [weak self] _ in
        self?.emitExternalDisplay()
      })
    streamObservers.append(
      center.addObserver(forName: UIScreen.didDisconnectNotification, object: nil, queue: .main) {
        [weak self] _ in
        self?.emitExternalDisplay()
      })
    updateCaptureObservation()
  }

  /// Stops event delivery. Safe to call when not observing.
  public func stopObserving() {
    streamObservers.forEach(NotificationCenter.default.removeObserver)
    streamObservers.removeAll()
    handler = nil
    updateCaptureObservation()
  }

  private func applyBlockCapture() {
    guard protection.blockCapture else {
      secureContainer.detach()
      blockCaptureFailure = nil
      return
    }
    blockCaptureFailure = attachSecureContainer()
  }

  /// Hosts the key window in the secure container; returns the unavailability reason on failure.
  private func attachSecureContainer() -> String? {
    if probe.isiOSAppOnMac {
      // On a Mac host the secure layer blanks the window on screen, not just in captures.
      secureContainer.detach()
      return "iosAppOnMac"
    }
    guard let window = probe.keyWindow() ?? secureContainer.attachedWindow else {
      return "noWindow"
    }
    let result = secureContainer.attach(to: window)
    guard result == .attached else { return result.rawValue }
    secureContainer.setSecure(true)
    return nil
  }

  @discardableResult
  private func publishState() -> ScreenProtectionState {
    screenProtectionState = ScreenProtectionState(
      captureBlocked: protection.blockCapture && blockCaptureFailure == nil,
      obscuresWhileCaptured: protection.obscureWhileCaptured,
      obscuresAppSwitcher: protection.obscureAppSwitcher,
      unavailable: blockCaptureFailure.map { ["blockCapture:\($0)"] } ?? [])
    return screenProtectionState
  }

  private func updateProtectionObservers() {
    guard protection != .off else {
      protectionObservers.forEach(NotificationCenter.default.removeObserver)
      protectionObservers.removeAll()
      return
    }
    guard protectionObservers.isEmpty else { return }
    let center = NotificationCenter.default
    protectionObservers.append(
      center.addObserver(
        forName: UIApplication.willResignActiveNotification, object: nil, queue: .main
      ) { [weak self] _ in
        self?.showObscuringView()
      })
    protectionObservers.append(
      center.addObserver(
        forName: UIApplication.didBecomeActiveNotification, object: nil, queue: .main
      ) { [weak self] _ in
        self?.applicationDidBecomeActive()
      })
  }

  private func applicationDidBecomeActive() {
    removeObscuringView()
    if let failure = blockCaptureFailure, Self.retriedBlockCaptureFailures.contains(failure) {
      applyBlockCapture()
      publishState()
    }
    updateCaptureCover()
  }

  /// One capture registration serves both event delivery and the capture cover.
  private func updateCaptureObservation() {
    let needed = handler != nil || protection.obscureWhileCaptured
    if needed, captureObservation == nil {
      captureObservation = probe.observeCaptureChanges { [weak self] in
        self?.captureStateChanged()
      }
    } else if !needed {
      captureObservation?.cancel()
      captureObservation = nil
    }
  }

  private func captureStateChanged() {
    let captured = probe.isScreenCaptured()
    handler?(
      HardeningSignal(
        type: .screenCaptureActive, metadata: ["active": captured, "source": probe.captureSource]))
    updateCaptureCover(captured: captured)
  }

  private func emitExternalDisplay() {
    let count = probe.screenCount - 1
    handler?(
      HardeningSignal(
        type: .externalDisplay,
        metadata: ["connected": count > 0, "displayCount": max(0, count)]))
  }

  private func updateCaptureCover(captured: Bool? = nil) {
    guard protection.obscureWhileCaptured, captured ?? probe.isScreenCaptured() else {
      captureCoverView?.removeFromSuperview()
      captureCoverView = nil
      return
    }
    guard captureCoverView == nil, let window = probe.keyWindow() else { return }
    let cover = UIView(frame: window.bounds)
    cover.backgroundColor = .black
    cover.autoresizingMask = [.flexibleWidth, .flexibleHeight]
    cover.accessibilityIdentifier = Self.captureCoverViewIdentifier
    window.addSubview(cover)
    captureCoverView = cover
  }

  private func showObscuringView() {
    guard protection.obscureAppSwitcher, obscuringView == nil, let window = probe.keyWindow()
    else { return }
    let view = UIVisualEffectView(effect: UIBlurEffect(style: .regular))
    view.frame = window.bounds
    view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
    view.accessibilityIdentifier = Self.obscuringViewIdentifier
    window.addSubview(view)
    obscuringView = view
  }

  private func removeObscuringView() {
    obscuringView?.removeFromSuperview()
    obscuringView = nil
  }
}

/// Environment reads behind the detectors; replaceable in tests.
protocol HardeningProbe {
  var screenCount: Int { get }
  var isApplicationActive: Bool { get }
  /// True when an iPhone/iPad app runs on an Apple silicon Mac.
  var isiOSAppOnMac: Bool { get }
  /// The API behind `isScreenCaptured()`: `"sceneCaptureState"` (iOS 17+) or `"screenIsCaptured"`.
  var captureSource: String { get }
  func keyWindow() -> UIWindow?
  func fileExists(atPath path: String) -> Bool
  func canOpen(scheme: String) -> Bool
  func loadedImageNames() -> [String]
  func isDebuggerAttached() -> Bool
  func isScreenCaptured() -> Bool
  /// Calls `onChange` on the main queue whenever the capture state may have changed.
  func observeCaptureChanges(_ onChange: @escaping () -> Void) -> CaptureObservation
  func hasCodeSignature() -> Bool
}

/// A live capture-state registration; `cancel()` ends it and is idempotent.
protocol CaptureObservation: AnyObject {
  func cancel()
}

struct SystemProbe: HardeningProbe {
  var screenCount: Int { UIScreen.screens.count }

  var isApplicationActive: Bool { UIApplication.shared.applicationState == .active }

  var isiOSAppOnMac: Bool { ProcessInfo.processInfo.isiOSAppOnMac }

  var captureSource: String {
    if #available(iOS 17.0, *) { return "sceneCaptureState" }
    return "screenIsCaptured"
  }

  /// Connected window scenes, foreground-active first. Apps on the app-delegate lifecycle still
  /// get one implicit window scene.
  static func windowScenes() -> [UIWindowScene] {
    let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
    return scenes.filter { $0.activationState == .foregroundActive }
      + scenes.filter { $0.activationState != .foregroundActive }
  }

  func keyWindow() -> UIWindow? {
    Self.windowScenes().lazy.compactMap { $0.windows.first(where: \.isKeyWindow) }.first
  }

  func fileExists(atPath path: String) -> Bool {
    FileManager.default.fileExists(atPath: path)
  }

  func canOpen(scheme: String) -> Bool {
    guard let url = URL(string: scheme) else { return false }
    return UIApplication.shared.canOpenURL(url)
  }

  func loadedImageNames() -> [String] {
    (0..<_dyld_image_count()).compactMap { index in
      _dyld_get_image_name(index).map { String(cString: $0) }
    }
  }

  func isDebuggerAttached() -> Bool {
    var process = kinfo_proc()
    var size = MemoryLayout<kinfo_proc>.stride
    var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
    let result = sysctl(&mib, u_int(mib.count), &process, &size, nil, 0)
    return result == 0 && (process.kp_proc.p_flag & P_TRACED) != 0
  }

  func isScreenCaptured() -> Bool {
    if #available(iOS 17.0, *) {
      return Self.windowScenes().contains { $0.traitCollection.sceneCaptureState == .active }
    }
    return UIScreen.main.isCaptured
  }

  func observeCaptureChanges(_ onChange: @escaping () -> Void) -> CaptureObservation {
    if #available(iOS 17.0, *) { return SceneCaptureStateObservation(onChange: onChange) }
    return ScreenCapturedObservation(onChange: onChange)
  }

  func hasCodeSignature() -> Bool {
    guard let executable = Bundle.main.executableURL,
      let data = try? Data(contentsOf: executable, options: .mappedIfSafe)
    else { return false }
    return Self.containsCodeSignature(data)
  }

  /// Scans little-endian 64-bit Mach-O load commands for `LC_CODE_SIGNATURE`.
  static func containsCodeSignature(_ data: Data) -> Bool {
    guard data.count >= 32 else { return false }
    let magic = data.prefix(4).withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }
    guard magic == 0xfeed_facf else { return false }
    let commandCount = data[16..<20].withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }
    var offset = 32
    for _ in 0..<min(commandCount, 4096) {
      guard offset + 8 <= data.count else { break }
      let command = data[offset..<(offset + 4)].withUnsafeBytes {
        $0.loadUnaligned(as: UInt32.self)
      }
      let commandSize = data[(offset + 4)..<(offset + 8)].withUnsafeBytes {
        $0.loadUnaligned(as: UInt32.self)
      }
      if command == 0x1d { return true }
      guard commandSize >= 8, Int(commandSize) <= data.count - offset else { break }
      offset += Int(commandSize)
    }
    return false
  }
}

/// iOS 15–16 capture changes: `UIScreen.capturedDidChangeNotification`.
final class ScreenCapturedObservation: CaptureObservation {
  private var token: NSObjectProtocol?

  init(onChange: @escaping () -> Void) {
    token = NotificationCenter.default.addObserver(
      forName: UIScreen.capturedDidChangeNotification, object: nil, queue: .main
    ) { _ in onChange() }
  }

  deinit {
    cancel()
  }

  func cancel() {
    token.map(NotificationCenter.default.removeObserver)
    token = nil
  }
}

/// iOS 17+ capture changes: the `UITraitSceneCaptureState` trait of every connected window scene,
/// including scenes that connect after registration.
@available(iOS 17.0, *)
final class SceneCaptureStateObservation: CaptureObservation {
  private struct Registration {
    weak var environment: AnyObject?
    let unregister: () -> Void
  }

  private let onChange: () -> Void
  private var registrations: [Registration] = []
  private var connectToken: NSObjectProtocol?

  init(onChange: @escaping () -> Void) {
    self.onChange = onChange
    for scene in SystemProbe.windowScenes() { register(scene) }
    connectToken = NotificationCenter.default.addObserver(
      forName: UIScene.willConnectNotification, object: nil, queue: .main
    ) { [weak self] notification in
      (notification.object as? UIWindowScene).map { self?.register($0) }
    }
  }

  deinit {
    cancel()
  }

  /// Follows the capture trait of `environment` (a window scene in production) until cancelled.
  /// The kit runs on the main thread, and scene notifications are delivered on `.main`.
  func register<Environment: UITraitChangeObservable & UITraitEnvironment>(
    _ environment: Environment
  ) {
    guard !registrations.contains(where: { $0.environment === environment }) else { return }
    let onChange = self.onChange
    let token = MainActor.assumeIsolated {
      environment.registerForTraitChanges([UITraitSceneCaptureState.self]) {
        (_: Environment, _: UITraitCollection) in onChange()
      }
    }
    registrations.append(
      Registration(environment: environment) { [weak environment] in
        MainActor.assumeIsolated { environment?.unregisterForTraitChanges(token) }
      })
  }

  func cancel() {
    connectToken.map(NotificationCenter.default.removeObserver)
    connectToken = nil
    let registrations = self.registrations
    self.registrations.removeAll()
    for registration in registrations { registration.unregister() }
  }
}
