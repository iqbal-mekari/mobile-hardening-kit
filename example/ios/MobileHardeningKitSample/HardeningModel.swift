import Combine
import MobileHardeningKit

/// Owns the kit and republishes its output for SwiftUI. Reports signals only; no policy decisions.
final class HardeningModel: ObservableObject {
  private let kit = MobileHardeningKit()

  @Published private(set) var snapshot: [HardeningSignal] = []
  @Published private(set) var events: [HardeningSignal] = []
  @Published private(set) var protectionState: ScreenProtectionState = .off
  @Published private(set) var findings: [HardeningSignal] = []
  @Published var screenProtection = false {
    didSet {
      // Best-effort on iOS: shows what the platform actually applied, including `unavailable`.
      protectionState = kit.setScreenProtection(
        screenProtection
          ? ScreenProtection(obscureWhileCaptured: true, obscureAppSwitcher: true) : .off)
    }
  }
  @Published var monitoring = false {
    didSet {
      if monitoring {
        // Report-only, foreground only; findings are delivered on the main queue.
        kit.startMonitoring(IntegrityMonitorConfig(interval: 30)) { [weak self] signal in
          guard let self else { return }
          self.findings = Array(([signal] + self.findings).prefix(20))
        }
      } else {
        kit.stopMonitoring()
      }
    }
  }

  func checkIntegrityNow() {
    kit.checkIntegrityNow()
  }

  func scan() {
    snapshot = kit.snapshot()
  }

  // Events are delivered on the main queue.
  func startObserving() {
    kit.startObserving { [weak self] signal in
      guard let self else { return }
      self.events = Array(([signal] + self.events).prefix(20))
    }
  }

  func stopObserving() {
    kit.stopObserving()
  }
}
