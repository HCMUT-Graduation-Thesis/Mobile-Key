package com.example.a100_basiccrypto.digitalkey.storage

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils.toHex
import java.security.SecureRandom

/**
 * Manages the App's own BLE Identity (IRK and Identity Address).
 * These are generated once and persisted securely using modern MasterKey API.
 */
class BleIdentityManager(context: Context) {

    companion object {
        private const val PREF_FILE = "ble_identity_prefs"
        private const val KEY_APP_IRK = "app_irk"
        private const val KEY_APP_ADDR = "app_ble_addr"
    }

    // Using modern MasterKey API instead of deprecated MasterKeys
    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val sharedPreferences = EncryptedSharedPreferences.create(
        context,
        PREF_FILE,
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    /**
     * Returns the persistent IRK of this App. Generates one if it doesn't exist.
     */
    fun getAppIrk(): ByteArray {
        val hex = sharedPreferences.getString(KEY_APP_IRK, null)
        if (hex != null) return hexToBytes(hex)

        val irk = ByteArray(16)
        SecureRandom().nextBytes(irk)
        sharedPreferences.edit().putString(KEY_APP_IRK, bytesToHex(irk)).apply()
        return irk
    }

    /**
     * Returns the persistent BLE Identity Address of this App.
     */
    fun getAppBleAddress(): ByteArray {
        val hex = sharedPreferences.getString(KEY_APP_ADDR, null)
        if (hex != null) return hexToBytes(hex)

        // Generate a random "Static Device Address" (6 bytes)
        // High 2 bits must be 11 for static addresses in BLE
        val addr = ByteArray(6)
        SecureRandom().nextBytes(addr)
        addr[0] = (addr[0].toInt() or 0xC0).toByte() 
        
        sharedPreferences.edit().putString(KEY_APP_ADDR, bytesToHex(addr)).apply()
        return addr
    }

    private fun bytesToHex(bytes: ByteArray): String = 
        bytes.joinToString("") { "%02x".format(it) }

    private fun hexToBytes(hex: String): ByteArray {
        val result = ByteArray(hex.length / 2)
        for (i in hex.indices step 2) {
            result[i / 2] = hex.substring(i, i + 2).toInt(16).toByte()
        }
        return result
    }
}
