import Foundation

/// Signal type identifiers. Raw values match the Dart `HardeningSignalType` names and the Android core.
public enum HardeningSignalType: String {
  case root
  case jailbreak
  case instrumentation
  case debuggerAttach
  case signatureMismatch
  case emulator
  case accessibilityUnrecognized
  case devModeEnabled
  case screenCaptureActive
  case screenshotTaken
  case externalDisplay
}

/// A point-in-time, heuristic observation. `metadata` is bounded and contains no user identifiers.
public struct HardeningSignal {
  public let type: HardeningSignalType
  public let observedAt: Date
  public let metadata: [String: Any]

  public init(type: HardeningSignalType, observedAt: Date = Date(), metadata: [String: Any] = [:]) {
    self.type = type
    self.observedAt = observedAt
    self.metadata = metadata
  }

  /// The `type` / `observedAt` / `metadata` map schema shared with the Flutter channel.
  public var dictionary: [String: Any] {
    [
      "type": type.rawValue,
      "observedAt": ISO8601DateFormatter().string(from: observedAt),
      "metadata": metadata,
    ]
  }
}
