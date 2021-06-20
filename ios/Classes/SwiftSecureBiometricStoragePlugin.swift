import Flutter
//import UIKit

public class SwiftSecureBiometricStoragePlugin: NSObject, FlutterPlugin {
  private let impl = SecureBiometricStorageImpl(storageError: { (code, message, details) -> Any in
    FlutterError(code: code, message: message, details: details)
  }, storageMethodNotImplemented: FlutterMethodNotImplemented)

  public static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(name: "secure_biometric_storage", binaryMessenger: registrar.messenger())
    let instance = SwiftSecureBiometricStoragePlugin()
    registrar.addMethodCallDelegate(instance, channel: channel)
  }
  
  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    impl.handle(StorageMethodCall(method: call.method, arguments: call.arguments), result: result)
  }
}
