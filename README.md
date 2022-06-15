# secure_biometric_storage

[![pub package](https://img.shields.io/pub/v/secure_biometric_storage.svg)](https://pub.dev/packages/secure_biometric_storage) 

Fork of [biometric_storage](https://pub.dev/packages/biometric_storage) with focus on security



Encrypted file store, **optionally** secured by a biometric lock 
for Android and iOS. 

Meant as a way to store small data in a hardware encrypted fashion. E.g. to 
store passwords, secret keys, etc. but not massive amounts
of data.

Uses similar encryption mechanism as in [flutter_secure_storage](https://pub.dev/packages/flutter_secure_storage)

* Android: Uses androidx with KeyStore.
* iOS: LocalAuthentication with KeyChain.

## Security Enhancements:

* On both Android and iOS keys are invalidated if new fingerprint/face are added. 
* [Auth-per-use](https://developer.android.com/training/sign-in/biometric-auth#auth-per-use-keys) keys are used for storages secured by a biometric lock.
* [BIOMETRIC_STRONG](https://developer.android.com/reference/androidx/biometric/BiometricManager.Authenticators#BIOMETRIC_STRONG) used on Android.

> An auth-per-use key requires the user to present a biometric credential 
> each time your app needs to access data that's guarded by that key. Auth-per-use keys can be useful 
> for high-value transactions, such as making a large payment or updating a person's health records.

## Getting Started

### Android
* Requirements:
  * Android: API Level >= 23
  * MainActivity must extend FlutterFragmentActivity
  * Theme for the main activity must use `Theme.AppCompat` theme.
    (Otherwise there will be crashes on Android < 29)
    For example: 
    
    **AndroidManifest.xml**:
    ```xml
    <activity
    android:name=".MainActivity"
    android:launchMode="singleTop"
    android:theme="@style/LaunchTheme"
    ```

    **xml/styles.xml**:
    ```xml
        <style name="LaunchTheme" parent="Theme.AppCompat.NoActionBar">
        <!-- Show a splash screen on the activity. Automatically removed when
             Flutter draws its first frame -->
        <item name="android:windowBackground">@drawable/launch_background</item>

        <item name="android:windowNoTitle">true</item>
        <item name="android:windowActionBar">false</item>
        <item name="android:windowFullscreen">true</item>
        <item name="android:windowContentOverlay">@null</item>
    </style>
    ```

### iOS

https://developer.apple.com/documentation/localauthentication/logging_a_user_into_your_app_with_face_id_or_touch_id

* include the NSFaceIDUsageDescription key in your app’s Info.plist file
* Requires at least iOS 9


## Resources

* https://developer.android.com/topic/security/data
* https://developer.android.com/topic/security/best-practices
* https://developer.android.com/training/sign-in/biometric-auth

