import UIKit

/// Outcome of hosting a window in a `SecureCaptureContainer`.
enum SecureCaptureAttachResult: String {
  case attached
  /// The window's layer has no superlayer yet (not on screen). Retry once the app is active.
  case windowNotReady
  /// The secure-entry text field did not expose the expected sublayer on this iOS version.
  case secureLayerUnavailable
}

/// Hosts a window's layer so that system captures may render it blank. Replaceable in tests.
protocol SecureCaptureContainer: AnyObject {
  /// The window currently hosted, if any.
  var attachedWindow: UIWindow? { get }
  /// Hosts `window`; re-attaching the attached window is a no-op that reports `.attached`.
  func attach(to window: UIWindow) -> SecureCaptureAttachResult
  /// Toggles secure rendering of the hosted window.
  func setSecure(_ secure: Bool)
  /// Restores the window's layer to its original superlayer and index. Safe when not attached.
  func detach()
}

/// Best-effort capture blanking, **not supported by Apple**.
///
/// UIKit renders the content of a secure-text-entry `UITextField` as blank in screenshots,
/// recordings, and mirroring. Reparenting the window's layer into that field's secure sublayer
/// extends the behaviour to the whole window. This depends on undocumented layer structure (the
/// secure sublayer is the field layer's last sublayer from iOS 17, its first before), so attach
/// validates the sublayer exists and reports `.secureLayerUnavailable` otherwise.
final class SystemSecureCaptureContainer: SecureCaptureContainer {
  private let makeField: () -> UITextField
  private let usesLastSublayer: Bool
  private var field: UITextField?
  private weak var originalSuperlayer: CALayer?
  private var originalIndex = 0
  private(set) weak var attachedWindow: UIWindow?

  /// Whether this iOS release keeps the secure sublayer last (iOS 17+) rather than first.
  static var secureSublayerIsLast: Bool {
    if #available(iOS 17.0, *) { return true }
    return false
  }

  init(
    usesLastSublayer: Bool = SystemSecureCaptureContainer.secureSublayerIsLast,
    makeField: @escaping () -> UITextField = { UITextField() }
  ) {
    self.usesLastSublayer = usesLastSublayer
    self.makeField = makeField
  }

  deinit {
    detach()
  }

  func attach(to window: UIWindow) -> SecureCaptureAttachResult {
    if field != nil, attachedWindow === window { return .attached }
    detach()
    guard let superlayer = window.layer.superlayer else { return .windowNotReady }

    let field = makeField()
    field.isSecureTextEntry = true
    field.isUserInteractionEnabled = false
    // Right-to-left layouts offset the secure sublayer, which would shift the hosted window.
    field.semanticContentAttribute = .forceLeftToRight
    // Let UIKit build the secure sublayer, then leave the view tree before reparenting layers: a
    // field that stays a subview of the window it hosts forms a circular hierarchy (iOS 26 crash).
    window.addSubview(field)
    field.layoutIfNeeded()
    field.removeFromSuperview()
    let sublayers = field.layer.sublayers ?? []
    guard let secureLayer = usesLastSublayer ? sublayers.last : sublayers.first else {
      return .secureLayerUnavailable
    }

    let index = superlayer.sublayers?.firstIndex(of: window.layer) ?? 0
    field.layer.frame = .zero
    superlayer.insertSublayer(field.layer, at: UInt32(index))
    secureLayer.addSublayer(window.layer)

    self.field = field
    originalSuperlayer = superlayer
    originalIndex = index
    attachedWindow = window
    return .attached
  }

  func setSecure(_ secure: Bool) {
    field?.isSecureTextEntry = secure
  }

  func detach() {
    guard let field else { return }
    if let window = attachedWindow {
      if let superlayer = originalSuperlayer {
        // The field layer sits at the original index; inserting there puts the window back in
        // front of it, so removing the field leaves the window exactly where it was.
        let count = superlayer.sublayers?.count ?? 0
        superlayer.insertSublayer(window.layer, at: UInt32(min(originalIndex, count)))
      } else {
        window.layer.removeFromSuperlayer()
      }
    }
    field.layer.removeFromSuperlayer()
    self.field = nil
    originalSuperlayer = nil
    attachedWindow = nil
  }
}
