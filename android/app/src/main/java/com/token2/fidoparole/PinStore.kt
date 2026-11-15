package com.token2.fidoparole

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The key's FIDO PIN, remembered on this phone.
 *
 * Encrypted with an AES-256-GCM key in the Android Keystore (hardware-backed
 * where the phone has it) that can only be used right after the user passes
 * the phone's fingerprint/face check or screen lock — every use, no grace
 * period. Adding a fingerprint or removing the screen lock destroys the key,
 * and with it the saved PIN. Nothing leaves the phone (backup is disabled).
 */
class PinStore(private val ctx: Context) {
    private val prefs = ctx.getSharedPreferences("saved_pin", Context.MODE_PRIVATE)

    /** Biometrics (strong) or, on Android 11+, also the screen lock PIN/pattern. */
    val authenticators: Int = if (Build.VERSION.SDK_INT >= 30) BIOMETRIC_STRONG or DEVICE_CREDENTIAL else BIOMETRIC_STRONG

    fun available(): Boolean = BiometricManager.from(ctx).canAuthenticate(authenticators) == BiometricManager.BIOMETRIC_SUCCESS

    fun has(): Boolean = prefs.contains(CT) && keystore().containsAlias(ALIAS)

    /** A cipher to encrypt a new PIN (fresh key); authenticate it, then [store]. */
    fun encryptCipher(): Cipher {
        val ks = keystore()
        if (ks.containsAlias(ALIAS)) ks.deleteEntry(ALIAS)
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
            .apply {
                if (Build.VERSION.SDK_INT >= 30) {
                    setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
                } else {
                    @Suppress("DEPRECATION") setUserAuthenticationValidityDurationSeconds(-1)
                }
            }
            .build()
        gen.init(spec)
        val key = gen.generateKey()
        return Cipher.getInstance(TRANSFORM).apply { init(Cipher.ENCRYPT_MODE, key) }
    }

    fun store(authenticated: Cipher, pin: String) {
        val ct = authenticated.doFinal(pin.toByteArray(Charsets.UTF_8))
        prefs.edit().putString(CT, b64(ct)).putString(IV, b64(authenticated.iv)).apply()
    }

    /** A cipher to decrypt the saved PIN, or null when there is none or it became invalid. */
    fun decryptCipher(): Cipher? {
        if (!prefs.contains(CT)) return null
        val iv = prefs.getString(IV, null) ?: return null
        val key = keystore().getKey(ALIAS, null) as? SecretKey ?: run { forget(); return null }
        return try {
            Cipher.getInstance(TRANSFORM).apply { init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, unb64(iv))) }
        } catch (_: KeyPermanentlyInvalidatedException) {
            forget(); null
        }
    }

    fun read(authenticated: Cipher): String {
        val ct = unb64(prefs.getString(CT, null) ?: error("no saved PIN"))
        val plain = authenticated.doFinal(ct)
        return try { String(plain, Charsets.UTF_8) } finally { plain.fill(0) }
    }

    fun forget() {
        prefs.edit().clear().apply()
        try { keystore().deleteEntry(ALIAS) } catch (_: Exception) {}
    }

    private fun keystore() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private fun b64(b: ByteArray) = Base64.encodeToString(b, Base64.NO_WRAP)
    private fun unb64(s: String) = Base64.decode(s, Base64.NO_WRAP)

    private companion object {
        const val ALIAS = "fidoparole-saved-pin"
        const val TRANSFORM = "AES/GCM/NoPadding"
        const val CT = "ct"
        const val IV = "iv"
    }
}
