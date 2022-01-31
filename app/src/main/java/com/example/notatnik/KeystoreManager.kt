package com.example.notatnik

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec

class KeystoreManager(ctx : Context, crypto : CryptoHelper) {
    private val IV_SIZE = 16
    private val KEY_SIZE = 256
    private val MASTER_KEY_ALIAS = "MASTER_KEY"
    private val SHARED_PREFERENCES_NAME = "settings"
    private val KEYSTORE_IV_NAME = "C9SNHGFFpE"
    private var applicationContext : Context = ctx
    private var cryptoHelper : CryptoHelper = crypto

    fun generateMasterKey() {
        val ks = KeyStore.getInstance("AndroidKeyStore")
        ks.load(null)
        if (!ks.containsAlias(MASTER_KEY_ALIAS)) generateKey()
    }


    private fun generateKey() {
        val keygen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val builder = KeyGenParameterSpec.Builder(MASTER_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(KEY_SIZE)


        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            if (applicationContext.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) {
                builder.setUnlockedDeviceRequired(true)
                    .setIsStrongBoxBacked(true)
            }
        }

        keygen.init(builder.build())
        keygen.generateKey()
    }

    fun getLocalEncryptionCipher() : Cipher {
        val ks = KeyStore.getInstance("AndroidKeyStore")
        ks.load(null)
        val key = ks.getKey(MASTER_KEY_ALIAS, null)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val preferences = applicationContext.getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE)
        var iv : ByteArray
        if (preferences.contains(KEYSTORE_IV_NAME)){
            iv = cryptoHelper.hexToByteArray(preferences.getString(KEYSTORE_IV_NAME, "")!!)
            val spec = GCMParameterSpec(IV_SIZE * Byte.SIZE_BITS, iv)
            cipher.init(Cipher.DECRYPT_MODE, key, spec)
            return cipher
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, key, cipher.parameters)
            val editor = preferences.edit()
            editor.putString(KEYSTORE_IV_NAME, cryptoHelper.byteArrayToHex(cipher.iv))
            editor.apply()
            return cipher
        }
    }

    fun encryptApplicationKey(pt: ByteArray, cipher: Cipher): ByteArray {
        return cipher.doFinal(pt)?: throw IllegalArgumentException("ENCRYPTION ERROR!")
    }

    fun decryptApplicationKey(ct: ByteArray, cipher: Cipher): ByteArray {
        return cipher.doFinal(ct)?: throw IllegalArgumentException("DECRYPTION ERROR!")
    }
}
