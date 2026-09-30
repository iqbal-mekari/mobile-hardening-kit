import Combine
import MobileHardeningKit

/// Owns the kit and republishes its output for SwiftUI. Reports signals only; no policy decisions.
final class HardeningModel: ObservableObject {
  private let kit = MobileHardeningKit()

  @Published private(set) var snapshot: [HardeningSignal] = []
  @Published private(set) var events: [HardeningSignal] = []
  @Published var screenProtection = false {
    didSet { kit.setScreenProtectionEnabled(screenProtection) }
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
