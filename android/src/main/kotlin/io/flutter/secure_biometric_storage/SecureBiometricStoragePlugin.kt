// Original work Copyright (c) 2019 Herbert Poul (@hpoul)
// Modified work Copyright (c) 2021 IT Service Omikron GmbH.
// Use of this source code is governed by a MIT license that can be
// found in the LICENSE file.

package io.flutter.secure_biometric_storage

import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.security.keystore.KeyPermanentlyInvalidatedException
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import com.squareup.moshi.JsonClass
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import io.flutter.plugin.common.PluginRegistry.Registrar
import mu.KotlinLogging
import java.io.PrintWriter
import java.io.StringWriter
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException

private val logger = KotlinLogging.logger {}

typealias ErrorCallback = (errorInfo: AuthenticationErrorInfo) -> Unit

class MethodCallException(
    val errorCode: String,
    val errorMessage: String?,
    val errorDetails: Any? = null
) : Exception(errorMessage ?: errorCode)


enum class CanAuthenticateResponse(val code: Int) {
    Success(BiometricManager.BIOMETRIC_SUCCESS),
    ErrorHwUnavailable(BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE),
    ErrorNoBiometricEnrolled(BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED),
    ErrorNoHardware(BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE),
    ErrorStatusUnknown(BiometricManager.BIOMETRIC_STATUS_UNKNOWN), ;

    override fun toString(): String {
        return "CanAuthenticateResponse.$name: $code"
    }
}

@Suppress("unused")
enum class AuthenticationError(val code: Int) {
    Canceled(BiometricPrompt.ERROR_CANCELED),
    Timeout(BiometricPrompt.ERROR_TIMEOUT),
    UserCanceled(BiometricPrompt.ERROR_USER_CANCELED),
    Lockout(BiometricPrompt.ERROR_LOCKOUT),
    LockoutPermanent(BiometricPrompt.ERROR_LOCKOUT_PERMANENT),

    Unknown(-1),

    /** Authentication valid, but unknown */
    Failed(-2),
    KeyPermanentlyInvalidated(-3),
    ;

    companion object {
        fun forCode(code: Int) =
            values().firstOrNull { it.code == code } ?: Unknown
    }
}

data class AuthenticationErrorInfo(
    val error: AuthenticationError,
    val message: CharSequence,
    val errorDetails: String? = null
) {
    constructor(
        error: AuthenticationError,
        message: CharSequence,
        e: Throwable
    ) : this(error, message, e.toCompleteString())
}

private fun Throwable.toCompleteString(): String {
    val out = StringWriter().let { out ->
        printStackTrace(PrintWriter(out))
        out.toString()
    }
    return "$this\n$out"
}

class SecureBiometricStoragePlugin : FlutterPlugin, ActivityAware, MethodCallHandler {

    companion object {

        // deprecated, used for v1 plugin api.
        @Suppress("unused")
        @JvmStatic
        fun registerWith(registrar: Registrar) {
            SecureBiometricStoragePlugin().apply {
                initialize(
                    registrar.messenger(),
                    registrar.context()
                )
                updateAttachedActivity(registrar.activity())
            }
        }

        const val PARAM_NAME = "name"
        const val PARAM_WRITE_CONTENT = "content"
        const val PARAM_ANDROID_PROMPT_INFO = "androidPromptInfo"

        val moshi = Moshi.Builder()
            .addLast(KotlinJsonAdapterFactory())
            .build() as Moshi

        val executor: ExecutorService = Executors.newSingleThreadExecutor()
        private val handler: Handler = Handler(Looper.getMainLooper())
    }

    private var attachedActivity: FragmentActivity? = null

    private val storageFiles = mutableMapOf<String, SecureBiometricStorageFile>()

    private val biometricManager by lazy { BiometricManager.from(applicationContext) }


    private lateinit var applicationContext: Context

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        initialize(binding.binaryMessenger, binding.applicationContext)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
    }

    private fun initialize(messenger: BinaryMessenger, context: Context) {
        this.applicationContext = context
        val channel = MethodChannel(messenger, "secure_biometric_storage")
        channel.setMethodCallHandler(this)
    }

    override fun onMethodCall(call: MethodCall, result: Result) {
        logger.trace { "onMethodCall(${call.method})" }
        try {
            fun <T> requiredArgument(name: String) =
                call.argument<T>(name) ?: throw MethodCallException(
                    "MissingArgument",
                    "Missing required argument '$name'"
                )

            // every method call requires the name of the stored file.
            val getName = { requiredArgument<String>(PARAM_NAME) }
            val getAndroidPromptInfo = {
                requiredArgument<Map<String, Any>>(PARAM_ANDROID_PROMPT_INFO).let {
                    moshi.adapter(AndroidPromptInfo::class.java).fromJsonValue(it)
                        ?: throw MethodCallException(
                            "BadArgument",
                            "'$PARAM_ANDROID_PROMPT_INFO' is not well formed"
                        )
                }
            }

            fun withStorage(cb: SecureBiometricStorageFile.() -> Unit) {
                val name = getName()
                storageFiles[name]?.apply(cb) ?: run {
                    logger.warn { "User tried to access storage '$name', before initialization" }
                    result.error("Storage $name was not initialized.", null, null)
                    return
                }
            }

            fun SecureBiometricStorageFile.withAuth(
                cipherOpMode: Int,
                cb: SecureBiometricStorageFile.(authenticationResult: BiometricPrompt.AuthenticationResult?) -> Unit
            ) {
                if (!options.authenticationRequired) {
                    return cb(null)
                }
                val promptInfo = getAndroidPromptInfo()
                authenticate(cipherOpMode, this, promptInfo, {
                    cb(it)
                }) { info ->
                    result.error(
                        "AuthError:${info.error}",
                        info.message.toString(),
                        info.errorDetails
                    )
                    logger.error("AuthError: $info")
                }
            }

            when (call.method) {
                "canAuthenticate" -> result.success(canAuthenticate().name)
                "getAvailableBiometrics" -> getAvailableBiometrics({ result.success(it) }) {
                    result.error(
                        "NoAvailableBiometrics",
                        "There were no available biometrics detected or something went wrong",
                        null
                    )
                }
                "init" -> {
                    val name = getName()
                    if (storageFiles.containsKey(name)) {
                        if (call.argument<Boolean>("forceInit") == true) {
                            throw MethodCallException(
                                "AlreadyInitialized",
                                "A storage file with the name '$name' was already initialized."
                            )
                        } else {
                            result.success(false)
                            return
                        }
                    }

                    val options = moshi.adapter(InitOptions::class.java)
                        .fromJsonValue(call.argument("options") ?: emptyMap<String, Any>())
                        ?: InitOptions()
                    storageFiles[name] =
                        SecureBiometricStorageFile(applicationContext, name, options)
                    result.success(true)
                }
                "read" -> withStorage {
                    if (exists()) {
                        withAuth(Cipher.DECRYPT_MODE) {
                            result.success(readFile(it))
                        }
                    } else {
                        result.success(null)
                    }
                }
                "write" -> withStorage {
                    withAuth(Cipher.ENCRYPT_MODE) {
                        writeFile(it, requiredArgument(PARAM_WRITE_CONTENT))
                        result.success(true)
                    }
                }
                "delete" -> withStorage {
                    result.success(deleteFile())
                }
                "deleteAll" -> {
                    for (file in storageFiles.values) {
                        file.deleteFile()
                    }
                    storageFiles.clear()
                    result.success(true)
                }
                else -> result.notImplemented()
            }
        } catch (e: MethodCallException) {
            logger.error(e) { "Error while processing method call ${call.method}" }
            result.error(e.errorCode, e.errorMessage, e.errorDetails)
        } catch (e: Exception) {
            logger.error(e) { "Error while processing method call '${call.method}'" }
            result.error("Unexpected Error", e.message, e.toCompleteString())
        }
    }

    private inline fun ui(crossinline onError: ErrorCallback, crossinline cb: () -> Unit) =
        handler.post {
            try {
                cb()
            } catch (e: IllegalBlockSizeException) {
                if (e.cause!!::class.java.name == "android.security.KeyStoreException") {
                    logger.error(e) { "Key was permanently invalidated" }
                    onError(
                        AuthenticationErrorInfo(
                            AuthenticationError.KeyPermanentlyInvalidated,
                            "key permanently invalidated. ${e.localizedMessage}",
                            e
                        )
                    )
                } else {
                    logger.error(e) { "Error while calling UI callback. This must not happen." }
                    onError(
                        AuthenticationErrorInfo(
                            AuthenticationError.Unknown,
                            "Unexpected authentication error. ${e.localizedMessage}",
                            e
                        )
                    )
                }
            } catch (e: Throwable) {
                logger.error(e) { "Error while calling UI callback. This must not happen." }
                onError(
                    AuthenticationErrorInfo(
                        AuthenticationError.Unknown,
                        "Unexpected authentication error. ${e.localizedMessage}",
                        e
                    )
                )
            }
        }

    private fun canAuthenticate(): CanAuthenticateResponse {
        val response: Int = biometricManager.canAuthenticate(BIOMETRIC_STRONG)

        return CanAuthenticateResponse.values().firstOrNull { it.code == response }
            ?: throw Exception(
                "Unknown response code {$response} (available: ${
                    CanAuthenticateResponse.values().contentToString()
                }"
            )
    }

    private fun getAvailableBiometrics(
        onSuccess: (result: ArrayList<String>) -> Unit,
        onError: () -> Unit
    ) {
        try {
            val activity = attachedActivity ?: return run {
                logger.error { "No attached activity." }
                onError()
            }
            if (!activity.isFinishing) {
                val biometrics: ArrayList<String> = getAvailableBiometrics(activity)
                onSuccess(biometrics)
            }
        } catch (e: java.lang.Exception) {
            onError()
        }
    }

    private fun getAvailableBiometrics(activity: FragmentActivity): ArrayList<String> {
        val biometrics: ArrayList<String> = ArrayList()
        val packageManager: PackageManager = activity.packageManager
        if (Build.VERSION.SDK_INT >= 23) {
            if (packageManager.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)) {
                biometrics.add("fingerprint")
            }
        }
        if (Build.VERSION.SDK_INT >= 29) {
            if (packageManager.hasSystemFeature(PackageManager.FEATURE_FACE)) {
                biometrics.add("face")
            }
            if (packageManager.hasSystemFeature(PackageManager.FEATURE_IRIS)) {
                biometrics.add("iris")
            }
        }
        return biometrics
    }

    private fun authenticate(
        cipherOpMode: Int,
        secureBiometricStorageFile: SecureBiometricStorageFile,
        promptInfo: AndroidPromptInfo,
        onSuccess: (result: BiometricPrompt.AuthenticationResult) -> Unit,
        onError: ErrorCallback
    ) {
        logger.trace("authenticate()")
        val activity = attachedActivity ?: return run {
            logger.error { "Plugin is not attached to an activity." }
            onError(
                AuthenticationErrorInfo(
                    AuthenticationError.Failed,
                    "Plugin is not attached to any activity."
                )
            )
        }

        // checking lifecycle state, see: https://stackoverflow.com/questions/56358422/java-lang-illegalstateexception-error-in-biometricprompt-authenticate
        val lifecycleState = activity.lifecycle.currentState
        if (lifecycleState != Lifecycle.State.RESUMED) return run{
            logger.error { "Wrong lifecycle state" }
            onError(
                    AuthenticationErrorInfo(
                            AuthenticationError.Failed,
                            "Wrong lifecycle state"
                    )
            )
        }

        val prompt =
            BiometricPrompt(activity, executor, object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    logger.trace("onAuthenticationError($errorCode, $errString)")
                    ui(onError) {
                        onError(
                            AuthenticationErrorInfo(
                                AuthenticationError.forCode(
                                    errorCode
                                ), errString
                            )
                        )
                    }
                }

                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    logger.trace("onAuthenticationSucceeded($result)")
                    ui(onError) { onSuccess(result) }
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    logger.trace("onAuthenticationFailed()")
                    // this can happen multiple times, so we don't want to communicate an error.
//                ui(onError) { onError(AuthenticationErrorInfo(AuthenticationError.Failed, "biometric is valid but not recognized")) }
                }
            })
        val cipher = secureBiometricStorageFile.getCipher()
        val secretKey = secureBiometricStorageFile.getSecretKey(cipherOpMode)

        if (cipherOpMode == Cipher.DECRYPT_MODE) {
            val ivParameterSpec = secureBiometricStorageFile.getIvParameterSpec()
            try {
                cipher.init(cipherOpMode, secretKey, ivParameterSpec)
            } catch (e: KeyPermanentlyInvalidatedException) {
                onError(
                    AuthenticationErrorInfo(
                        AuthenticationError.KeyPermanentlyInvalidated,
                        "Key was permanently invalidated. User may have enrolled new biometrics"
                    )
                )
                return
            }
        } else {
            cipher.init(cipherOpMode, secretKey)
        }


        prompt.authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle(promptInfo.title)
                .setSubtitle(promptInfo.subtitle)
                .setDescription(promptInfo.description)
                .setNegativeButtonText(promptInfo.negativeButton)
                .setConfirmationRequired(promptInfo.confirmationRequired)
                .setAllowedAuthenticators(BIOMETRIC_STRONG)
                .build(), BiometricPrompt.CryptoObject(cipher)
        )
    }

    override fun onDetachedFromActivity() {
        logger.trace { "onDetachedFromActivity" }
        attachedActivity = null
    }

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
    }

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        logger.debug { "Attached to new activity." }
        updateAttachedActivity(binding.activity)
    }

    private fun updateAttachedActivity(activity: Activity?) {
        if (activity !is FragmentActivity) {
            logger.error { "Got attached to activity which is not a FragmentActivity: $activity" }
            return
        }
        attachedActivity = activity
    }

    override fun onDetachedFromActivityForConfigChanges() {
    }
}

@JsonClass(generateAdapter = true)
data class AndroidPromptInfo(
    val title: String,
    val subtitle: String?,
    val description: String?,
    val negativeButton: String,
    val confirmationRequired: Boolean
)
