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
  private var handler: ((HardeningSignal) -> Void)?
  private var streamObservers: [NSObjectProtocol] = []
  private var protectionObservers: [NSObjectProtocol] = []
  private var screenProtectionEnabled = false
  private var obscuringView: UIView?

  /// Accessibility identifier of the app-switcher blur overlay.
  public static let obscuringViewIdentifier = "mobile_hardening_kit_background_obscuring_view"

  public init() {}

  deinit {
    stopObserving()
    stopProtectionObservation()
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
    ].filter { FileManager.default.fileExists(atPath: $0) }
    let suspiciousSchemes = ["cydia://", "sileo://"].filter { scheme in
      guard let url = URL(string: scheme) else { return false }
      return UIApplication.shared.canOpenURL(url)
    }
    if !jailbreakPaths.isEmpty || !suspiciousSchemes.isEmpty {
      add(
        .jailbreak,
        ["artifacts": Array(jailbreakPaths.prefix(8)), "urlSchemes": suspiciousSchemes])
    }

    let injectionNames = ["frida", "substrate", "substitute", "libhooker", "ellekit", "xposed"]
    var injectedLibraries: [String] = []
    for index in 0..<_dyld_image_count() {
      guard let image = _dyld_get_image_name(index) else { continue }
      let name = String(cString: image).lowercased()
      if injectionNames.contains(where: name.contains) {
        injectedLibraries.append(String(name.suffix(120)))
      }
    }
    if !injectedLibraries.isEmpty {
      add(.instrumentation, ["artifacts": Array(injectedLibraries.prefix(8))])
    }

    var process = kinfo_proc()
    var size = MemoryLayout<kinfo_proc>.stride
    var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
    let result = sysctl(&mib, u_int(mib.count), &process, &size, nil, 0)
    if result == 0 && (process.kp_proc.p_flag & P_TRACED) != 0 {
      add(.debuggerAttach, ["traced": true])
    }

    #if targetEnvironment(simulator)
      add(.emulator, ["environment": "simulator"])
    #endif

    if UIScreen.main.isCaptured {
      add(.screenCaptureActive, ["captured": true])
    }
    if UIScreen.screens.count > 1 {
      add(.externalDisplay, ["displayCount": UIScreen.screens.count - 1])
    }

    // iOS does not expose its app-signing certificate fingerprint to sandboxed
    // applications. Report only if the signed main executable lacks a code signature.
    if !mainExecutableHasCodeSignature() {
      add(.signatureMismatch, ["codeSignaturePresent": false])
    }
    return signals
  }

  /// Enables or disables the app-switcher blur overlay. Opt-in, disabled by default.
  /// iOS has no supported API to prevent screenshots or screen recording.
  public func setScreenProtectionEnabled(_ enabled: Bool) {
    screenProtectionEnabled = enabled
    if enabled {
      startProtectionObservation()
      if UIApplication.shared.applicationState != .active { updateObscuringView() }
    } else {
      stopProtectionObservation()
    }
  }

  /// Starts delivering capture, screenshot, and external-display changes to `handler`.
  public func startObserving(_ handler: @escaping (HardeningSignal) -> Void) {
    stopObserving()
    self.handler = handler
    let center = NotificationCenter.default
    streamObservers.append(
      center.addObserver(forName: UIScreen.capturedDidChangeNotification, object: nil, queue: .main)
      { [weak self] _ in
        guard let self else { return }
        self.emit(.screenCaptureActive, UIScreen.main.isCaptured)
      })
    streamObservers.append(
      center.addObserver(
        forName: UIApplication.userDidTakeScreenshotNotification, object: nil, queue: .main
      ) { [weak self] _ in
        self?.emit(.screenshotTaken, true)
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
  }

  /// Stops event delivery. Safe to call when not observing.
  public func stopObserving() {
    streamObservers.forEach(NotificationCenter.default.removeObserver)
    streamObservers.removeAll()
    handler = nil
  }

  private func mainExecutableHasCodeSignature() -> Bool {
    guard let executable = Bundle.main.executableURL,
      let data = try? Data(contentsOf: executable, options: .mappedIfSafe),
      data.count >= 32
    else { return false }
    // Mach-O LC_CODE_SIGNATURE command; handles little-endian 64-bit binaries.
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

  private func startProtectionObservation() {
    guard protectionObservers.isEmpty else { return }
    let center = NotificationCenter.default
    protectionObservers.append(
      center.addObserver(
        forName: UIApplication.willResignActiveNotification, object: nil, queue: .main
      ) { [weak self] _ in
        self?.updateObscuringView()
      })
    protectionObservers.append(
      center.addObserver(
        forName: UIApplication.didBecomeActiveNotification, object: nil, queue: .main
      ) { [weak self] _ in
        self?.removeObscuringView()
      })
  }

  private func stopProtectionObservation() {
    protectionObservers.forEach(NotificationCenter.default.removeObserver)
    protectionObservers.removeAll()
    removeObscuringView()
  }

  private func emit(_ type: HardeningSignalType, _ active: Bool) {
    handler?(HardeningSignal(type: type, metadata: ["active": active]))
  }

  private func emitExternalDisplay() {
    let count = UIScreen.screens.count - 1
    handler?(
      HardeningSignal(
        type: .externalDisplay,
        metadata: ["connected": count > 0, "displayCount": max(0, count)]))
  }

  private func updateObscuringView() {
    guard screenProtectionEnabled, obscuringView == nil,
      let window = UIApplication.shared.windows.first(where: { $0.isKeyWindow })
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
