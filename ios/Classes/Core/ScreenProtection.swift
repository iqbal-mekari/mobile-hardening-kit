import Foundation

/// Requested window protection. Every option is opt-in and off by default.
///
/// - `blockCapture`: **best-effort and not supported by Apple.** Hosts the key window's layer in
///   the secure-text-entry layer of an off-screen `UITextField` so that screenshots, recordings,
///   and mirroring may render it blank. It relies on undocumented UIKit behaviour that can change
///   in any iOS release; never treat it as a guarantee.
/// - `obscureWhileCaptured`: covers the key window with an opaque view while the screen is
///   recorded, mirrored, or AirPlayed. Reactive: the first frames of a capture can leak.
/// - `obscureAppSwitcher`: blurs the key window while the app is inactive, hiding content from the
///   app-switcher snapshot.
public struct ScreenProtection: Equatable {
  public var blockCapture: Bool
  public var obscureWhileCaptured: Bool
  public var obscureAppSwitcher: Bool

  /// No protection.
  public static let off = ScreenProtection()

  public init(
    blockCapture: Bool = false, obscureWhileCaptured: Bool = false,
    obscureAppSwitcher: Bool = false
  ) {
    self.blockCapture = blockCapture
    self.obscureWhileCaptured = obscureWhileCaptured
    self.obscureAppSwitcher = obscureAppSwitcher
  }
}

/// Protection the platform actually applied for a `ScreenProtection` request.
public struct ScreenProtectionState: Equatable {
  public let captureBlocked: Bool
  public let obscuresWhileCaptured: Bool
  public let obscuresAppSwitcher: Bool
  /// `<option>:<reason>` entries for requested options that could not be applied, for example
  /// `blockCapture:windowNotReady`.
  public let unavailable: [String]

  /// Nothing applied and nothing requested.
  public static let off = ScreenProtectionState(
    captureBlocked: false, obscuresWhileCaptured: false, obscuresAppSwitcher: false,
    unavailable: [])

  public init(
    captureBlocked: Bool, obscuresWhileCaptured: Bool, obscuresAppSwitcher: Bool,
    unavailable: [String]
  ) {
    self.captureBlocked = captureBlocked
    self.obscuresWhileCaptured = obscuresWhileCaptured
    self.obscuresAppSwitcher = obscuresAppSwitcher
    self.unavailable = unavailable
  }

  /// The map shape shared with the Flutter channel and the Android core.
  public func toMap() -> [String: Any] {
    [
      "captureBlocked": captureBlocked,
      "obscuresWhileCaptured": obscuresWhileCaptured,
      "obscuresAppSwitcher": obscuresAppSwitcher,
      "unavailable": unavailable,
    ]
  }
}
