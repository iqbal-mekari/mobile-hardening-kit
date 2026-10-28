import Flutter

/// Flutter adapter: maps channel calls onto the native `MobileHardeningKit` core.
public class MobileHardeningKitPlugin: NSObject, FlutterPlugin, FlutterStreamHandler {
  private let kit: MobileHardeningKit
  /// Handler of the integrity-monitor stream; separate from the screen-events handler (`self`).
  let integrityStreamHandler: IntegrityStreamHandler

  public override init() {
    let kit = MobileHardeningKit()
    self.kit = kit
    integrityStreamHandler = IntegrityStreamHandler(kit: kit)
    super.init()
  }

  public static func register(with registrar: FlutterPluginRegistrar) {
    let methods = FlutterMethodChannel(
      name: "mobile_hardening_kit", binaryMessenger: registrar.messenger())
    let events = FlutterEventChannel(
      name: "mobile_hardening_kit/events", binaryMessenger: registrar.messenger())
    let integrityEvents = FlutterEventChannel(
      name: "mobile_hardening_kit/integrity_events", binaryMessenger: registrar.messenger())
    let instance = MobileHardeningKitPlugin()
    registrar.addMethodCallDelegate(instance, channel: methods)
    events.setStreamHandler(instance)
    integrityEvents.setStreamHandler(instance.integrityStreamHandler)
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    switch call.method {
    case "snapshot": result(kit.snapshot().map(\.dictionary))
    case "setScreenProtection":
      let arguments = call.arguments as? [String: Any]
      func option(_ key: String) -> Bool { arguments?[key] as? Bool ?? false }
      let protection = ScreenProtection(
        blockCapture: option("blockCapture"),
        obscureWhileCaptured: option("obscureWhileCaptured"),
        obscureAppSwitcher: option("obscureAppSwitcher"))
      result(kit.setScreenProtection(protection).toMap())
    case "checkIntegrityNow":
      kit.checkIntegrityNow()
      result(nil)
    default: result(FlutterMethodNotImplemented)
    }
  }

  public func onListen(withArguments arguments: Any?, eventSink events: @escaping FlutterEventSink)
    -> FlutterError?
  {
    kit.startObserving { events($0.dictionary) }
    return nil
  }

  public func onCancel(withArguments arguments: Any?) -> FlutterError? {
    kit.stopObserving()
    return nil
  }
}

/// Streams integrity-monitor findings. The core delivers the start pass synchronously inside
/// `startMonitoring`; that is safe here because Flutter hands over a live sink in `onListen`.
final class IntegrityStreamHandler: NSObject, FlutterStreamHandler {
  private static let defaultIntervalMs = 30_000.0
  private let kit: MobileHardeningKit

  init(kit: MobileHardeningKit) {
    self.kit = kit
  }

  func onListen(withArguments arguments: Any?, eventSink events: @escaping FlutterEventSink)
    -> FlutterError?
  {
    // Missing or invalid values fall back to the defaults; the certificate and trusted
    // accessibility packages are Android-only and ignored.
    let arguments = arguments as? [String: Any]
    let intervalMs = (arguments?["intervalMs"] as? NSNumber)?.doubleValue ?? Self.defaultIntervalMs
    let config = IntegrityMonitorConfig(
      interval: intervalMs / 1000, checkOnResume: arguments?["checkOnResume"] as? Bool ?? true)
    kit.startMonitoring(config) { events($0.dictionary) }
    return nil
  }

  func onCancel(withArguments arguments: Any?) -> FlutterError? {
    kit.stopMonitoring()
    return nil
  }
}
