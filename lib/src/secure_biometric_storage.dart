// Original work Copyright (c) 2019 Herbert Poul (@hpoul)
// Modified work Copyright (c) 2021 IT Service Omikron GmbH.
// Use of this source code is governed by a MIT license that can be
// found in the LICENSE file.

import 'dart:async';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:logging/logging.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

final _logger = Logger('secure_biometric_storage');

/// Reason for not supporting authentication.
/// **As long as this is NOT [unsupported] you can still use the secure
/// storage without biometric storage** (By setting
/// [StorageFileInitOptions.authenticationRequired] to `false`).
enum CanAuthenticateResponse {
  success,
  errorHwUnavailable,
  errorNoBiometricEnrolled,
  errorNoHardware,
  // https://developer.android.com/reference/androidx/biometric/BiometricManager?hl=en#BIOMETRIC_STATUS_UNKNOWN
  statusUnknown,

  /// Plugin does not support platform. This should no longer be the case.
  unsupported,
}

const _canAuthenticateMapping = {
  'Success': CanAuthenticateResponse.success,
  'ErrorHwUnavailable': CanAuthenticateResponse.errorHwUnavailable,
  'ErrorNoBiometricEnrolled': CanAuthenticateResponse.errorNoBiometricEnrolled,
  'ErrorNoHardware': CanAuthenticateResponse.errorNoHardware,
  'ErrorUnknown': CanAuthenticateResponse.unsupported,
  'ErrorStatusUnknown': CanAuthenticateResponse.statusUnknown,
};

enum AuthExceptionCode {
  userCanceled,
  unknown,
  timeout,
  keyPermanentlyInvalidated,
  lockout,
  lockoutPermanent,
}

const _authErrorCodeMapping = {
  'AuthError:UserCanceled': AuthExceptionCode.userCanceled,
  'AuthError:Timeout': AuthExceptionCode.timeout,
  'AuthError:KeyPermanentlyInvalidated': AuthExceptionCode.keyPermanentlyInvalidated,
  'AuthError:Lockout': AuthExceptionCode.lockoutPermanent,
  'AuthError:LockoutPermanent': AuthExceptionCode.lockoutPermanent,
};

class SecureBiometricStorageException implements Exception {
  SecureBiometricStorageException(this.message);

  final String message;

  @override
  String toString() {
    return 'SecureBiometricStorageException{message: $message}';
  }
}

/// Exceptions during authentication operations.
/// See [AuthExceptionCode] for details.
class AuthException implements Exception {
  AuthException(this.code, this.message);

  final AuthExceptionCode code;
  final String message;

  @override
  String toString() {
    return 'AuthException{code: $code, message: $message}';
  }
}

class StorageFileInitOptions {
  StorageFileInitOptions({
    this.authenticationRequired = true,
  });

  /// Whether an authentication is required. if this is
  /// false NO BIOMETRIC CHECK WILL BE PERFORMED! and the value
  /// will simply be save encrypted. (default: true)
  final bool authenticationRequired;

  Map<String, dynamic> toJson() => <String, dynamic>{
        'authenticationRequired': authenticationRequired,
      };
}

/// Android specific configuration of the prompt displayed for biometry.
class AndroidPromptInfo {
  const AndroidPromptInfo({
    this.title = 'Authenticate to unlock data',
    this.subtitle,
    this.description,
    this.negativeButton = 'Cancel',
    this.confirmationRequired = true,
  })  : assert(title != null),
        assert(negativeButton != null),
        assert(confirmationRequired != null);

  final String title;
  final String subtitle;
  final String description;
  final String negativeButton;
  final bool confirmationRequired;

  static const defaultValues = AndroidPromptInfo();

  Map<String, dynamic> _toJson() => <String, dynamic>{
        'title': title,
        'subtitle': subtitle,
        'description': description,
        'negativeButton': negativeButton,
        'confirmationRequired': confirmationRequired,
      };
}

/// Types of biometric hardware
enum BiometricType {
  iris,
  face,
  fingerprint,

  /// Plugin does not support this biometric type. This should no longer be the case.
  unknown,
}

const _biometricTypeMapping = {
  'iris': BiometricType.iris,
  'face': BiometricType.face,
  'fingerprint': BiometricType.fingerprint,
};

/// Main plugin class to interact with. Is always a singleton right now,
/// factory constructor will always return the same instance.
///
/// * call [canAuthenticate] to check support on the platform/device.
/// * call [getAvailableBiometrics] to get supported biometric hardware
/// * call [getStorage] to initialize a storage.
abstract class SecureBiometricStorage extends PlatformInterface {
  // Returns singleton instance.
  factory SecureBiometricStorage() => _instance;

  SecureBiometricStorage.create() : super(token: _token);

  static SecureBiometricStorage _instance = MethodChannelSecureBiometricStorage();

  /// Platform-specific plugins should set this with their own platform-specific
  /// class that extends [SecureBiometricStorage] when they register themselves.
  static set instance(SecureBiometricStorage instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  static const Object _token = Object();

  /// Returns whether this device supports biometric/secure storage or
  /// the reason [CanAuthenticateResponse] why it is not supported.
  Future<CanAuthenticateResponse> canAuthenticate();

  /// Return available biometric capabilities.
  /// * On Android: returns available hardware capabilities (must not be enrolled)
  /// * On iOS: returns enrolled biometrics
  Future<List<BiometricType>> getAvailableBiometrics();

  /// Retrieves the given biometric storage file.
  /// Each store is completely separated, and has it's own encryption and
  /// biometric lock.
  /// if [forceInit] is true, will throw an exception if the store was already
  /// created in this runtime.
  Future<SecureBiometricStorageFile> getStorage(
    String name, {
    StorageFileInitOptions options,
    bool forceInit = false,
    AndroidPromptInfo androidPromptInfo = AndroidPromptInfo.defaultValues,
  });

  /// returns true if and only if files are
  /// successfully deleted; false otherwise
  Future<void> deleteAll();

  @protected
  Future<String> read(
    String name,
    AndroidPromptInfo androidPromptInfo,
  );

  /// returns true if and only if the file is
  /// successfully deleted; false otherwise
  @protected
  Future<bool> delete(
    String name,
    AndroidPromptInfo androidPromptInfo,
  );

  @protected
  Future<void> write(
    String name,
    String content,
    AndroidPromptInfo androidPromptInfo,
  );
}

class MethodChannelSecureBiometricStorage extends SecureBiometricStorage {
  MethodChannelSecureBiometricStorage() : super.create();

  static const MethodChannel _channel = MethodChannel('secure_biometric_storage');

  @override
  Future<CanAuthenticateResponse> canAuthenticate() async {
    if (Platform.isAndroid || Platform.isIOS) {
      return _canAuthenticateMapping[await _channel.invokeMethod<String>('canAuthenticate')];
    }
    return CanAuthenticateResponse.unsupported;
  }

  @override
  Future<List<BiometricType>> getAvailableBiometrics() async {
    if (Platform.isAndroid || Platform.isIOS) {
      final results = await _channel.invokeMethod<List<Object>>('getAvailableBiometrics');
      return results.map((typeName) => _biometricTypeMapping[typeName] ?? BiometricType.unknown).toList();
    } else {
      throw UnimplementedError();
    }
  }

  /// Retrieves the given biometric storage file.
  /// Each store is completely separated, and has it's own encryption and
  /// biometric lock.
  /// if [forceInit] is true, will throw an exception if the store was already
  /// created in this runtime.
  @override
  Future<SecureBiometricStorageFile> getStorage(
    String name, {
    StorageFileInitOptions options,
    bool forceInit = false,
    AndroidPromptInfo androidPromptInfo = AndroidPromptInfo.defaultValues,
  }) async {
    assert(name != null);
    try {
      final result = await _channel.invokeMethod<bool>(
        'init',
        {
          'name': name,
          'options': options?.toJson() ?? StorageFileInitOptions().toJson(),
          'forceInit': forceInit,
        },
      );
      _logger.finest('getting storage. was created: $result');
      return SecureBiometricStorageFile(
        this,
        name,
        androidPromptInfo,
      );
    } catch (e, stackTrace) {
      _logger.warning('Error while initializing biometric storage.', e, stackTrace);
      rethrow;
    }
  }

  @override
  Future<String> read(
    String name,
    AndroidPromptInfo androidPromptInfo,
  ) =>
      _transformErrors(_channel.invokeMethod<String>('read', <String, dynamic>{
        'name': name,
        ..._androidPromptInfoOnlyOnAndroid(androidPromptInfo),
      }));

  @override
  Future<bool> delete(
    String name,
    AndroidPromptInfo androidPromptInfo,
  ) =>
      _transformErrors(_channel.invokeMethod<bool>('delete', <String, dynamic>{
        'name': name,
        ..._androidPromptInfoOnlyOnAndroid(androidPromptInfo),
      }));

  @override
  Future<void> deleteAll() => _transformErrors(_channel.invokeMethod<bool>('deleteAll', <String, dynamic>{}));

  @override
  Future<void> write(
    String name,
    String content,
    AndroidPromptInfo androidPromptInfo,
  ) =>
      _transformErrors(_channel.invokeMethod('write', <String, dynamic>{
        'name': name,
        'content': content,
        ..._androidPromptInfoOnlyOnAndroid(androidPromptInfo),
      }));

  Map<String, dynamic> _androidPromptInfoOnlyOnAndroid(AndroidPromptInfo promptInfo) {
    // Don't expose Android configurations to other platforms
    return Platform.isAndroid ? <String, dynamic>{'androidPromptInfo': promptInfo._toJson()} : <String, dynamic>{};
  }

  Future<T> _transformErrors<T>(Future<T> future) => future.catchError((dynamic error, StackTrace stackTrace) {
        _logger.warning('Error during plugin operation (details: ${error.details})', error, stackTrace);
        if (error is PlatformException) {
          if (error.code.startsWith('AuthError:')) {
            return Future<T>.error(
              AuthException(
                _authErrorCodeMapping[error.code] ?? AuthExceptionCode.unknown,
                error.message,
              ),
              stackTrace,
            );
          }
        }
        return Future<T>.error(error, stackTrace);
      });
}

class SecureBiometricStorageFile {
  SecureBiometricStorageFile(this._plugin, this.name, this.androidPromptInfo);

  final SecureBiometricStorage _plugin;
  final String name;
  final AndroidPromptInfo androidPromptInfo;

  /// read from the secure file and returns the content.
  /// Will return `null` if file does not exist.
  Future<String> read() => _plugin.read(name, androidPromptInfo);

  /// Write content of this file. Previous value will be overwritten.
  Future<void> write(String content) => _plugin.write(name, content, androidPromptInfo);

  /// Delete the content of this storage.
  Future<void> delete() => _plugin.delete(name, androidPromptInfo);
}
