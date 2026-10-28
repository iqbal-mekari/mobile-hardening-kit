import Flutter

/// Flutter adapter: maps channel calls onto the native `MobileHardeningKit` core.
public class MobileHardeningKitPlugin: NSObject, FlutterPlugin, FlutterStreamHandler {
  private let kit = MobileHardeningKit()

  public static func register(with registrar: FlutterPluginRegistrar) {
    let methods = FlutterMethodChannel(
      name: "mobile_hardening_kit", binaryMessenger: registrar.messenger())
    let events = FlutterEventChannel(
      name: "mobile_hardening_kit/events", binaryMessenger: registrar.messenger())
    let instance = MobileHardeningKitPlugin()
    registrar.addMethodCallDelegate(instance, channel: methods)
    events.setStreamHandler(instance)
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
