package com.example.notatnik

import android.content.Context
import android.content.SharedPreferences
import android.os.Bundle
import android.text.InputType
import android.util.Base64
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import java.security.spec.KeySpec
import java.util.Base64.getEncoder
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

class MainActivity : AppCompatActivity() {
    private val MIN_PASSWORD_LENGTH = 12;
    private lateinit var etNote : EditText
    private lateinit var etPassword : EditText
    private lateinit var bLock : Button
    private lateinit var secureLocalManager: SecureLocalManager
    companion object {
        const val PASSWORD_NAME = "08fiD82Pzk"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        etNote = findViewById(R.id.editTextNote)
        etPassword = findViewById(R.id.editTextPassword)
        bLock = findViewById(R.id.buttonLogin)
        secureLocalManager = SecureLocalManager(applicationContext)
        bLock.setOnClickListener {
            authenticate()
        }
        isAppLocked()
    }

    private fun isAppLocked(): Boolean {
        val preferences = applicationContext.getSharedPreferences(SecureLocalManager.SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE)
        return if (preferences.contains(SecureLocalManager.SECRET_TEXT_NAME)){
            bLock.text = "UNLOCK"
            etNote.setText(preferences.getString(SecureLocalManager.SECRET_TEXT_NAME, ""))
            etNote.isEnabled = false
            true
        } else{
            etNote.isEnabled = true
            bLock.text = "LOCK"
            false
        }
    }

    private fun generateKey(password: CharArray): SecretKey {
        val preferences = applicationContext.getSharedPreferences(SecureLocalManager.SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE)
        val salt = secureLocalManager.getSalt()
        val iterations = 1000
        val keyLength = 256
        val secretKeyFactory: SecretKeyFactory =
            SecretKeyFactory.getInstance("PBKDF2withHmacSHA256")
        val keySpec: KeySpec = PBEKeySpec(password, salt, iterations, keyLength)
        return secretKeyFactory.generateSecret(keySpec)
    }

    private fun encryptAndSaveData(): String? {
        val encrypted = secureLocalManager.encryptLocalData(etNote.text.toString().toByteArray())
        val b64 = Base64.encodeToString(encrypted, Base64.NO_WRAP)

        val preferences = applicationContext.getSharedPreferences(SecureLocalManager.SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE)
        val editor = preferences.edit()
        editor.putString(SecureLocalManager.SECRET_TEXT_NAME, b64).commit()

        Toast.makeText(applicationContext, "Data successfully encrypted", Toast.LENGTH_SHORT).show()
        return b64
    }

    private fun loadAndDecryptData(): String?{
        val preferences = applicationContext.getSharedPreferences(SecureLocalManager.SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE)
        val encrypted = preferences.getString(SecureLocalManager.SECRET_TEXT_NAME, "")
        preferences.edit().remove(SecureLocalManager.SECRET_TEXT_NAME).commit()
        val decrypted = secureLocalManager.decryptLocalData(Base64.decode(encrypted, Base64.NO_WRAP))

        Toast.makeText(applicationContext, "Data decrypted, you can edit your note now", Toast.LENGTH_SHORT).show()

        return String(decrypted)
    }

    private fun onUnlock() {
        val cipher = secureLocalManager.getLocalEncryptionCipher()
        secureLocalManager.loadOrGenerateApplicationKey(cipher)
        if (isAppLocked()) {
            val pt = loadAndDecryptData()
            etNote.setText(pt)
        } else {
            val ct = encryptAndSaveData()
            etNote.setText(ct)
        }
        isAppLocked()
    }

    private fun resetPassword() {
        val sharedPreferences = getSharedPreferences(SecureLocalManager.SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE)
        val editText = EditText(this)
        editText.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        val alert = AlertDialog.Builder(this)
        alert.setView(editText)
        alert.setMessage("Wrong password, enter old password to reset")
            .setPositiveButton("ok", null)
            .setNegativeButton("cancel", null)

        val dialog = alert.create()
        dialog.setOnShowListener {
            val button = dialog.getButton(AlertDialog.BUTTON_POSITIVE)
            button.setOnClickListener {
                val oldPassword = editText.text.toString()
                if (oldPassword.isNotEmpty()) {
                    if (Base64.encodeToString(
                            generateKey(
                                oldPassword.toCharArray()
                            ).encoded,
                            Base64.NO_WRAP
                        ) == sharedPreferences.getString(PASSWORD_NAME, null)
                    ) { // poprawne hasło
                        sharedPreferences.edit().remove(PASSWORD_NAME).commit()
                        Toast.makeText(
                            this,
                            "Password reset, log in with new password",
                            Toast.LENGTH_SHORT
                        ).show()
                        dialog.dismiss()
                    }
                }
            }
        }
        dialog.show()
    }

    private fun authenticate() {
        val sharedPreferences = getSharedPreferences(SecureLocalManager.SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE)
        if (sharedPreferences.contains(PASSWORD_NAME)) { // hasło jest już zapisane
            if (Base64.encodeToString(
                    generateKey(
                        etPassword.text.toString().toCharArray()
                    ).encoded,
                    Base64.NO_WRAP
                ) == sharedPreferences.getString(PASSWORD_NAME, null)
            ) {
                // you're in
                onUnlock()
            } else { // reset hasła
                resetPassword()
            }

        } else if (etPassword.text.toString().length >= MIN_PASSWORD_LENGTH) { // tworzenie hasła
            val hashed = generateKey(
                etPassword.text.toString().toCharArray()
            ).encoded
            val b64 = Base64.encodeToString(hashed, Base64.NO_WRAP)
            sharedPreferences.edit().putString(PASSWORD_NAME, b64).commit()
            Toast.makeText(this, "Password saved", Toast.LENGTH_SHORT).show()
            // you're in
            onUnlock()
        } else { // hasło nie spełnia wymagań
            Toast.makeText(
                this,
                "Password must be at least $MIN_PASSWORD_LENGTH characters long.",
                Toast.LENGTH_SHORT
            ).show()
        }
    }
}