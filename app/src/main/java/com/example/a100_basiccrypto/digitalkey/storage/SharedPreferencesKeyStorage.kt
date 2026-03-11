package com.example.a100_basiccrypto.digitalkey.storage

import android.content.Context
import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import com.example.a100_basiccrypto.digitalkey.core.KeyState
import com.example.a100_basiccrypto.digitalkey.core.Role
import com.example.a100_basiccrypto.digitalkey.crypto.CryptoUtils.hexToBytes
import com.example.a100_basiccrypto.digitalkey.crypto.CryptoUtils.toHex

class SharedPreferencesKeyStorage(context: Context) : IKeyStorageManager {
    private val prefs = context.getSharedPreferences("digital_key_prefs", Context.MODE_PRIVATE)

    override fun saveDigitalKey(record: DigitalKeyRecord) {
        prefs.edit().apply {
            putString("key_id", record.keyID?.toHex())
            putString("module_id", record.moduleID?.toHex())
            putInt("slot_id", record.slotID.toInt())
            putString("device_public_key", record.devicePublicKey?.toHex())
            putString("vehicle_public_key", record.vehiclePublicKey?.toHex())
            putString("fast_auth_key", record.fastAuthKey?.toHex())
            putString("immobilizer_token", record.immobilizerToken?.toHex())
            putInt("transaction_counter", record.transactionCounter)
            putString("role", record.role.name)
            putString("key_state", record.keyState.name)
            putString("friendly_name", record.friendlyName)
            apply()
        }
    }

    override fun getDigitalKey(): DigitalKeyRecord? {
        val keyIdHex = prefs.getString("key_id", null) ?: return null
        return DigitalKeyRecord().apply {
            keyID = keyIdHex.hexToBytes()
            moduleID = prefs.getString("module_id", null)?.hexToBytes()
            slotID = prefs.getInt("slot_id", 0).toByte()
            devicePublicKey = prefs.getString("device_public_key", null)?.hexToBytes()
            vehiclePublicKey = prefs.getString("vehicle_public_key", null)?.hexToBytes()
            fastAuthKey = prefs.getString("fast_auth_key", null)?.hexToBytes()
            immobilizerToken = prefs.getString("immobilizer_token", null)?.hexToBytes()
            transactionCounter = prefs.getInt("transaction_counter", 0)
            role = Role.valueOf(prefs.getString("role", Role.OWNER.name) ?: Role.OWNER.name)
            keyState = KeyState.valueOf(prefs.getString("key_state", KeyState.UNPAIRED.name) ?: KeyState.UNPAIRED.name)
            friendlyName = prefs.getString("friendly_name", "") ?: ""
        }
    }

    override fun updateTransactionCounter(counter: Int) {
        prefs.edit().putInt("transaction_counter", counter).apply()
    }

    override fun clearAll() {
        prefs.edit().clear().apply()
    }
}
