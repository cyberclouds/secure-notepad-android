package com.example.notatnik

import javax.crypto.Cipher
import android.content.Context.MODE_PRIVATE
import android.content.Context


class SecureLocalManager(ctxt: Context) {
    companion object {
        const val SHARED_PREFERENCES_NAME = "settings"
        const val APPLICATION_KEY_NAME = "lTtwCay8Nz"
        const val SECRET_TEXT_NAME = "udpMwgrkEO"
        const val SALT_NAME = "allP7ECEyl"
        const val IV_SIZE = 16
    }

    private var keystoreManager: KeystoreManager
    private var cryptoHelper: CryptoHelper
    private lateinit var applicationKey : ByteArray
    private var applicationContext : Context

    init {
        applicationContext = ctxt
        cryptoHelper = CryptoHelper()
        keystoreManager = KeystoreManager(applicationContext, cryptoHelper)
        keystoreManager.generateMasterKey()
        generateSalt()
    }

    private fun generateSalt() {
        val preferences = applicationContext.getSharedPreferences(SHARED_PREFERENCES_NAME, MODE_PRIVATE)
        if (preferences.contains(SALT_NAME)) return
        val salt = cryptoHelper.byteArrayToHex(cryptoHelper.generateIV())
        preferences.edit().putString(SALT_NAME, salt).apply()
    }

    fun getSalt() : ByteArray {
        val preferences = applicationContext.getSharedPreferences(SHARED_PREFERENCES_NAME, MODE_PRIVATE)
        return cryptoHelper.hexToByteArray(preferences.getString(SALT_NAME, "")!!)
    }

    fun encryptLocalData(data: ByteArray):ByteArray {
        val iv = cryptoHelper.generateIV(IV_SIZE)
        return iv + cryptoHelper.encryptData(data, applicationKey, iv)
    }

    fun decryptLocalData(data: ByteArray):ByteArray {
        val iv = data.sliceArray(0 .. IV_SIZE-1)
        val ct = data.sliceArray(IV_SIZE.. data.lastIndex)
        return cryptoHelper.decryptData(ct, applicationKey, iv)
    }

    fun getLocalEncryptionCipher():Cipher{
        return keystoreManager.getLocalEncryptionCipher()
    }

    fun loadOrGenerateApplicationKey(cipher: Cipher){
        val preferences = applicationContext.getSharedPreferences(SHARED_PREFERENCES_NAME, MODE_PRIVATE)
        if (preferences.contains(APPLICATION_KEY_NAME)) {
            val encryptedAppKey = preferences.getString(APPLICATION_KEY_NAME, "")!!
            applicationKey = keystoreManager.decryptApplicationKey(cryptoHelper.hexToByteArray(encryptedAppKey), cipher)
        }
        else{
            applicationKey = cryptoHelper.generateApplicationKey()
            val editor = preferences.edit()
            val encryptedAppKey = cryptoHelper.byteArrayToHex(keystoreManager.encryptApplicationKey(applicationKey, cipher))
            editor.putString(APPLICATION_KEY_NAME, encryptedAppKey)
            editor.apply()
        }
    }
}