// Original work Copyright (c) 2019 Herbert Poul (@hpoul)
// Modified work Copyright (c) 2021 IT Service Omikron GmbH.
// Use of this source code is governed by a MIT license that can be
// found in the LICENSE file.

package io.flutter.secure_biometric_storage

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricPrompt
import com.squareup.moshi.JsonClass
import mu.KotlinLogging
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

private val logger = KotlinLogging.logger {}

@JsonClass(generateAdapter = true)
data class InitOptions(
        val authenticationValidityDurationSeconds: Int = 30,
        val authenticationRequired: Boolean = true
)

class SecureBiometricStorageFile(
        context: Context,
        baseName: String,
        val options: InitOptions
) {

    companion object {
        /**
         * Name of directory inside private storage where all encrypted files are stored.
         */
        private const val DIRECTORY_NAME = "secure_biometric_storage"
        private const val FILE_SUFFIX = ".txt"
        private const val BACKUP_SUFFIX = "bak"
        private const val KEYSTORE_PROVIDER_ANDROID = "AndroidKeyStore"
    }

    private val secretKeyName = "${baseName}_secret_key"
    private val fileName = "$baseName$FILE_SUFFIX"
    private val file: File


    init {

        val baseDir = File(context.noBackupFilesDir, DIRECTORY_NAME)
        if (!baseDir.exists()) {
            baseDir.mkdirs()
        }
        file = File(baseDir, fileName)

        logger.trace { "Initialized $this with $options" }
    }

    private fun getKeyGenParameterSpec(): KeyGenParameterSpec {
        val keyGenParameterSpecBuilder = KeyGenParameterSpec.Builder(
                secretKeyName,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .setUserAuthenticationRequired(options.authenticationRequired)



        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            // Invalidate the keys if the user has registered a new biometric
            // credential, such as a new fingerprint. Can call this method only
            // on Android 7.0 (API level 24) or higher. The variable
            // "invalidatedByBiometricEnrollment" is true by default.
            // This applies only to keys which require user authentication (see setUserAuthenticationRequired(boolean))
            // and if no positive validity duration has been set
            keyGenParameterSpecBuilder.setInvalidatedByBiometricEnrollment(true)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            keyGenParameterSpecBuilder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        } else {
            keyGenParameterSpecBuilder.setUserAuthenticationValidityDurationSeconds(-1)
        }

        return keyGenParameterSpecBuilder.build()
    }


    private fun generateSecretKey(keyGenParameterSpec: KeyGenParameterSpec) {
        val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER_ANDROID)
        keyGenerator.init(keyGenParameterSpec)
        keyGenerator.generateKey()
    }

    fun exists() = file.exists()

    @Synchronized
    fun writeFile(authenticationResult: BiometricPrompt.AuthenticationResult?, content: String) {
        val newFile = File(file.parent, file.name)

        val bytes = content.toByteArray()
        logger.debug { "authenticationRequired is ${options.authenticationRequired}" }

        val cipher: Cipher = if (options.authenticationRequired) {
            if (authenticationResult != null) {
                authenticationResult.cryptoObject!!.cipher!!
            } else {
                throw IllegalArgumentException("AuthenticationResult was null. This should not be the case. Something went wrong.")
            }
        } else {
            val cipher = getCipher()
            cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(Cipher.ENCRYPT_MODE))
            cipher
        }

        val encryptedInfo: ByteArray = encrypt(cipher, bytes)

        // Write to a file.
        try {
            if (file.exists()) {
                val backupFile = File(file.parent, "${file.name}$BACKUP_SUFFIX")
                if (backupFile.exists()) {
                    backupFile.delete()
                }
                file.renameTo(backupFile)
            }
            FileOutputStream(newFile).use { out ->
                out.write(encryptedInfo)
                out.flush()
            }
            logger.debug { "Successfully written ${bytes.size} bytes." }
        } catch (ex: IOException) {
            // Error occurred opening file for writing.
            logger.error(ex) { "Error while writing encrypted file $file" }
        } catch (ex: NullPointerException) {
            // Error occurred opening file for writing.
            logger.error(ex) { "Error while writing encrypted file $file" }
        }
    }

    @Synchronized
    fun readFile(authenticationResult: BiometricPrompt.AuthenticationResult?): String? {
        if (!file.exists()) {
            logger.debug { "File $file does not exist. returning null." }
            return null
        }
        return try {
            val newFile = File(file.parent, file.name)

            val bytes = FileInputStream(newFile).use { input ->
                input.readBytes()
            }
            val cipher: Cipher = if (options.authenticationRequired) {
                if (authenticationResult != null) {
                    authenticationResult.cryptoObject!!.cipher!!
                } else {
                    throw IllegalArgumentException("AuthenticationResult was null. This should not be the case. Something went wrong.")
                }
            } else {
                val secretKey = getSecretKey(Cipher.DECRYPT_MODE)
                val cipher = getCipher()
                val ivParameterSpec = getIvParameterSpec()

                cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec)

                cipher
            }

            val decryptedInfo: ByteArray = decrypt(cipher, bytes)
            String(decryptedInfo)
        } catch (ex: IOException) {
            // Error occurred opening file for writing.
            logger.error(ex) { "Error while reading encrypted file $file" }
            null
        }
    }

    @Synchronized
    fun deleteFile(): Boolean {
        return file.delete()
    }

    /**
     * saves encrypted payload along with IV vector
     * (see https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Initialization_vector_.28IV.29)
     * stores data as follows:
     * [ivSize(size of Integer in bytes)|iv(ivSize)|payload(length of payload in bytes)]
     */
    private fun encrypt(cipher: Cipher, input: ByteArray): ByteArray {

        val payload: ByteArray = cipher.doFinal(input)
        val iv = cipher.parameters.getParameterSpec(IvParameterSpec::class.java).iv


        val ivSizeByteArray = ByteBuffer.allocate(Int.SIZE_BYTES).putInt(iv.size).array()
        val combined = ByteArray(ivSizeByteArray.size + iv.size + payload.size)

        System.arraycopy(ivSizeByteArray, 0, combined, 0, ivSizeByteArray.size)
        System.arraycopy(iv, 0, combined, ivSizeByteArray.size, iv.size)
        System.arraycopy(payload, 0, combined, ivSizeByteArray.size + iv.size, payload.size)


        return combined
    }

    /**
     * extracts payload from save file and decrypts
     */
    private fun decrypt(cipher: Cipher, input: ByteArray): ByteArray {
        val ivSizeByteArraySize = Int.SIZE_BYTES
        val ivSize = cipher.parameters.getParameterSpec(IvParameterSpec::class.java).iv.size

        val payloadSize: Int = input.size - ivSize - ivSizeByteArraySize
        val payload = ByteArray(payloadSize)
        System.arraycopy(input, ivSizeByteArraySize + ivSize, payload, 0, payloadSize)
        return cipher.doFinal(payload)
    }

    override fun toString(): String {
        return "SecureBiometricStorageFile(masterKeyName='$secretKeyName', fileName='$fileName', file=$file)"
    }

    fun getSecretKey(cipherOpMode: Int): SecretKey {
        if (cipherOpMode == Cipher.ENCRYPT_MODE) {
            generateSecretKey(getKeyGenParameterSpec())
        }

        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        // Before the keystore can be accessed, it must be loaded.
        keyStore.load(null)
        return keyStore.getKey(secretKeyName, null) as SecretKey
    }

    fun getCipher(): Cipher {
        return Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
                + KeyProperties.BLOCK_MODE_CBC + "/"
                + KeyProperties.ENCRYPTION_PADDING_PKCS7)
    }

    /**
     * extracts initialization vector(iv) from saved file
     */
    fun getIvParameterSpec(): IvParameterSpec? {
        if (!file.exists()) {
            logger.debug { "File $file does not exist. returning null." }
            return null
        }
        return try {
            val newFile = File(file.parent, file.name)

            val bytes = FileInputStream(newFile).use { input ->
                input.readBytes()
            }

            val ivSizeByteArray = ByteArray(Int.SIZE_BYTES)
            System.arraycopy(bytes, 0, ivSizeByteArray, 0, ivSizeByteArray.size)
            val ivSize = ByteBuffer.wrap(ivSizeByteArray).int

            val iv = ByteArray(ivSize)
            System.arraycopy(bytes, ivSizeByteArray.size, iv, 0, iv.size)

            IvParameterSpec(iv)


        } catch (ex: IOException) {
            // Error occurred opening file for writing.
            logger.error(ex) { "Error while reading encrypted file $file" }
            null
        }
    }

}
