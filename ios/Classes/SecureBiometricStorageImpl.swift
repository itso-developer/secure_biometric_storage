// Original work Copyright (c) 2019 Herbert Poul (@hpoul)
// Modified work Copyright (c) 2021 IT Service Omikron GmbH.
// Use of this source code is governed by a MIT license that can be
// found in the LICENSE file.

import Foundation
import LocalAuthentication

typealias StorageCallback = (Any?) -> Void
typealias StorageError = (String, String?, Any?) -> Any

struct StorageMethodCall {
    let method: String
    let arguments: Any?
}

class InitOptions {
    init(params: [String: Any]) {
        authenticationValidityDurationSeconds = params["authenticationValidityDurationSeconds"] as? Int
        authenticationRequired = params["authenticationRequired"] as? Bool
    }
    let authenticationValidityDurationSeconds: Int!
    let authenticationRequired: Bool!
}

private func hpdebug(_ message: String) {
    print(message);
}

class SecureBiometricStorageImpl {
    
    init(storageError: @escaping StorageError, storageMethodNotImplemented: Any) {
        self.storageError = storageError
        self.storageMethodNotImplemented = storageMethodNotImplemented
    }
    
    private var stores: [String: InitOptions] = [:]
    private let storageError: StorageError
    private let storageMethodNotImplemented: Any
    private let serviceStorageName = "flutter_secure_biometric_storage"
    private let domainStatePrefix =  "flutter_secure_biometric_storage" + "_domain_state_for_"
    private func storageError(code: String, message: String?, details: Any?) -> Any {
        return storageError(code, message, details)
    }
    
    private func baseQuery(name: String) -> [String: Any] {
        return [kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: serviceStorageName,
                kSecAttrAccount as String: name]
    }
    
    public func handle(_ call: StorageMethodCall, result: @escaping StorageCallback) {
        
        func requiredArg<T>(_ name: String, _ cb: (T) -> Void) {
            guard let args = call.arguments as? Dictionary<String, Any> else {
                result(storageError(code: "InvalidArguments", message: "Invalid arguments \(String(describing: call.arguments))", details: nil))
                return
            }
            guard let value = args[name] else {
                result(storageError(code: "InvalidArguments", message: "Missing argument \(name)", details: nil))
                return
            }
            guard let valueTyped = value as? T else {
                result(storageError(code: "InvalidArguments", message: "Invalid argument for \(name): expected \(T.self) got \(value)", details: nil))
                return
            }
            cb(valueTyped)
            return
        }
        
        if ("canAuthenticate" == call.method) {
            canAuthenticate(result: result)
        } else if("getAvailableBiometrics" == call.method) {
                      getAvailableBiometrics(result)
        } else if ("init" == call.method) {
            requiredArg("name") { name in
                requiredArg("options") { options in
                    stores[name] = InitOptions(params: options)
                }
            }
            result(true)
        } else if ("dispose" == call.method) {
            // nothing to dispose
            result(true)
        } else if ("read" == call.method) {
            requiredArg("name") { name in
                read(name, result)
            }
        } else if ("write" == call.method) {
            requiredArg("name") { name in
                requiredArg("content") { content in
                    write(name, content, result)
                }
            }
        } else if ("delete" == call.method) {
            requiredArg("name") { name in
                delete(name, result)
            }
        } else if("deleteAll" == call.method) {
            deleteAll(result)
        } else {
            result(storageMethodNotImplemented)
        }
    }
    
    private func read(_ name: String, _ result: @escaping StorageCallback) {
        
        var query = baseQuery(name: name)
        let context = LAContext()
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        query[kSecUseAuthenticationContext as String] = context
        query[kSecUseOperationPrompt as String] = "Unlock to access data"
        query[kSecReturnAttributes as String] = true
        query[kSecReturnData as String] = true
        
        var item: CFTypeRef?
        
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        hpdebug("the return status is \(status)")
        guard status != errSecItemNotFound else {
            let oldState =  UserDefaults.standard.string(forKey: domainStatePrefix + name)
            let domainState = context.evaluatedPolicyDomainState?.base64EncodedString()
            
            if (oldState != nil && oldState != domainState) {
                handleOSStatusError(status, result, "key may be permanently invalidated. \(status)")
                return
            } else {
                result(nil)
                return
            }
            
            
        }
        guard status == errSecSuccess else {
            handleOSStatusError(status, result, "Error retrieving item. \(status)")
            return
        }
        
        guard let existingItem = item as? [String : Any],
              let data = existingItem[kSecValueData as String] as? Data,
              let dataString = String(data: data, encoding: String.Encoding.utf8)
        
        
        else {
            result(storageError(code: "RetrieveError", message: "Unexpected data.", details: nil))
            return
        }
        result(dataString)
    }
    
    private func delete(_ name: String, _ result: @escaping StorageCallback) {
        let query = baseQuery(name: name)
        //    query[kSecMatchLimit as String] = kSecMatchLimitOne
        //    query[kSecReturnData as String] = true
        let status = SecItemDelete(query as CFDictionary)
        if (status == errSecSuccess) {
            UserDefaults.standard.removeObject(forKey: domainStatePrefix + name)
        } else {
            handleOSStatusError(status, result, "writing data")
            return
        }
        result(true)
    }
    
    private func write(_ name: String, _ content: String, _ result: @escaping StorageCallback) {
        guard let initOptions = stores[name] else {
            result(storageError(code: "WriteError", message: "Storage was not initialized. \(name)", details: nil))
            return
        }
        
        var query = baseQuery(name: name)
        
        let context = LAContext()
        
        if (initOptions.authenticationRequired) {
            
            let access: SecAccessControl = SecureBiometricStorageImpl.getBioSecAccessControl()
            
            context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
            
            // Ignore any error.
            query.merge([
                kSecUseAuthenticationContext as String: context,
                kSecAttrAccessControl as String: access,
                kSecUseOperationPrompt as String: "Unlock to save data",
            ]) { (_, new) in new }
        } else {
            hpdebug("No authentication required for \(name)")
        }
        query.merge([
            //      kSecMatchLimit as String: kSecMatchLimitOne,
            kSecValueData as String: content.data(using: String.Encoding.utf8) as Any,
        ]) { (_, new) in new }
        var status = SecItemAdd(query as CFDictionary, nil)
        if (status == errSecDuplicateItem) {
            hpdebug("Value already exists. updating.")
            let update = [kSecValueData as String: query[kSecValueData as String]]
            query.removeValue(forKey: kSecValueData as String)
            status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        }
        if (status == errSecSuccess) {
            if(initOptions.authenticationRequired) {
                let state = context.evaluatedPolicyDomainState?.base64EncodedString()
                UserDefaults.standard.setValue(state, forKey: domainStatePrefix + name)
            }
        }  else {
            handleOSStatusError(status, result, "writing data")
            return
        }
        result(nil)
    }
    
    func deleteAll(_ result: @escaping StorageCallback) {
        let spec: NSDictionary = [kSecAttrService as String: serviceStorageName,
                                  kSecClass as String: kSecClassGenericPassword,]
        let status = SecItemDelete(spec)
        if (status == errSecSuccess) {
            for key in UserDefaults.standard.dictionaryRepresentation().keys {
                if key.hasPrefix(domainStatePrefix) {
                    UserDefaults.standard.removeObject(forKey: key)
                }
            }
            result(nil)
        } else {
            handleOSStatusError(status, result, "deleting all data")
            return
        }
        
    }

    private func getAvailableBiometrics(_ result: @escaping StorageCallback) {
            var error: NSError?
            let context = LAContext()
            guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
                result(["undefined"])
                return
            }

            if #available(iOS 11.0, *) {
                switch context.biometryType {
                case .touchID:
                    result(["fingerprint"])
                case .faceID:
                    result(["face"])
                default:
                    result([])
                }
            }

            context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) ? result(["fingerprint"]) : result([])

        }
    
    static func getBioSecAccessControl() -> SecAccessControl {
        var access: SecAccessControl?
        var error: Unmanaged<CFError>?
        
        if #available(iOS 11.3, *) {
            access = SecAccessControlCreateWithFlags(nil,
                                                     kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                     .biometryCurrentSet,
                                                     &error)
        } else {
            access = SecAccessControlCreateWithFlags(nil,
                                                     kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                     .touchIDCurrentSet,
                                                     &error)
        }
        precondition(access != nil, "SecAccessControlCreateWithFlags failed")
        return access!
    }
    
    private func handleOSStatusError(_ status: OSStatus, _ result: @escaping StorageCallback, _ message: String) {
        var errorMessage: String? = nil
        if #available(iOS 11.3, OSX 10.12, *) {
            errorMessage = SecCopyErrorMessageString(status, nil) as String?
        }
        let code: String
        switch status {
        case errSecUserCanceled:
            code = "AuthError:UserCanceled"
        case errSecItemNotFound:
            code = "AuthError:KeyPermanentlyInvalidated"
        default:
            code = "SecurityError"
        }
        
        result(storageError(code: code, message: "Error while \(message): \(status): \(errorMessage ?? "Unknown")", details: nil))
    }
    
    private func canAuthenticate(result: @escaping StorageCallback) {
        let context = LAContext()
        if #available(iOS 10.0, OSX 10.12, *) {
            context.localizedCancelTitle = "Checking auth support"
        }
        var error: NSError?
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            result("Success")
            return
        }
        guard let err = error else {
            result("ErrorUnknown")
            return
        }
        let laError = LAError(_nsError: err)
        NSLog("LAError: \(laError)");
        switch laError.code {
        case .touchIDNotAvailable:
            result("ErrorHwUnavailable")
            break;
        case .passcodeNotSet: fallthrough
        case .touchIDNotEnrolled:
            result("ErrorNoBiometricEnrolled")
            break;
        case .invalidContext: fallthrough
        default:
            result("ErrorUnknown")
            break;
        }
    }
}
