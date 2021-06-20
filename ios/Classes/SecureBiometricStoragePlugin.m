#import "SecureBiometricStoragePlugin.h"
#import <secure_biometric_storage/secure_biometric_storage-Swift.h>

@implementation SecureBiometricStoragePlugin
+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar>*)registrar {
  [SwiftSecureBiometricStoragePlugin registerWithRegistrar:registrar];
}
@end
