package com.example.a100_basiccrypto

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.example.a100_basiccrypto.shared.model.KeyState
import com.example.a100_basiccrypto.shared.command.MessageConstants.INS_LOCK
import com.example.a100_basiccrypto.shared.command.MessageConstants.INS_START_ENGINE
import com.example.a100_basiccrypto.shared.command.MessageConstants.INS_UNLOCK
import com.example.a100_basiccrypto.digitalkey.storage.PasswordManager
import com.example.a100_basiccrypto.digitalkey.storage.SecureKeyStorageManager

class MainActivity : AppCompatActivity() {

    private lateinit var tvKeyName: TextView
    private lateinit var tvKeyState: TextView
    private lateinit var tvAccountId: TextView
    
    private lateinit var tvMetadataBrand: TextView
    private lateinit var tvMetadataPlate: TextView
    private lateinit var tvMetadataColor: TextView
    
    private lateinit var btnUnlock: Button
    private lateinit var btnLock: Button
    private lateinit var btnStart: Button
    
    private lateinit var btnSavePassword: Button
    private lateinit var etPairingPassword: EditText
    private lateinit var btnClearKeys: Button
    
    private val storageManager by lazy { SecureKeyStorageManager(this) }

    private val nfcReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            runOnUiThread { refreshKeyStateUI() }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // 1. Initialize Views
        initViews()

        // 2. Setup Listeners for Quick Actions
        setupActionListeners()

        // 3. Setup Setup Listeners
        btnSavePassword.setOnClickListener {
            val pairingPassword = etPairingPassword.text.toString()
            if (pairingPassword.isNotEmpty()) {
                PasswordManager.setPassword(this, pairingPassword)
                Toast.makeText(this, "Credentials Updated", Toast.LENGTH_SHORT).show()
            }
        }

        btnClearKeys.setOnClickListener {
            storageManager.clearAll()
            refreshKeyStateUI()
            Toast.makeText(this, "System Reset", Toast.LENGTH_SHORT).show()
        }

        // Load existing password
        etPairingPassword.setText(PasswordManager.getPassword(this))

        refreshKeyStateUI()

        // Register Receiver for NFC logs
        val filter = IntentFilter("com.example.a100_basiccrypto.LOG_ACTION")
        registerReceiver(nfcReceiver, filter, RECEIVER_EXPORTED)
    }

    private fun initViews() {
        tvKeyName = findViewById(R.id.tv_key_name)
        tvKeyState = findViewById(R.id.tv_key_state)
        tvAccountId = findViewById(R.id.tv_account_id)
        tvMetadataBrand = findViewById(R.id.tv_metadata_brand)
        tvMetadataPlate = findViewById(R.id.tv_metadata_plate)
        tvMetadataColor = findViewById(R.id.tv_metadata_color)
        btnUnlock = findViewById(R.id.btn_unlock)
        btnLock = findViewById(R.id.btn_lock)
        btnStart = findViewById(R.id.btn_start)
        btnSavePassword = findViewById(R.id.btn_save_password)
        etPairingPassword = findViewById(R.id.et_pairing_password)
        btnClearKeys = findViewById(R.id.btn_clear_keys)
    }

    private fun setupActionListeners() {
        btnUnlock.setOnClickListener { performAction(INS_UNLOCK, "UNLOCK") }
        btnLock.setOnClickListener { performAction(INS_LOCK, "LOCK") }
        btnStart.setOnClickListener { performAction(INS_START_ENGINE, "START ENGINE") }
    }

    private fun performAction(ins: Byte, actionName: String) {
        val latestKey = storageManager.getAllKeys().lastOrNull { it.core.keyState == KeyState.ACTIVE }

        if (latestKey != null) {
            // 1. Simulate Transaction logic
            val nextCounter = latestKey.core.transactionCounter + 1
            storageManager.updateTransactionCounter(latestKey.core.keyID!!, nextCounter)

            Toast.makeText(this, "$actionName Success", Toast.LENGTH_SHORT).show()

            // Re-sync UI
            refreshKeyStateUI()
        } else {
            Toast.makeText(this, "Action Denied: No Active Key", Toast.LENGTH_SHORT).show()
        }
    }

    private fun refreshKeyStateUI() {
        val keys = storageManager.getAllKeys()
        val latestKey = keys.lastOrNull()

        if (latestKey != null) {
            tvKeyName.text = "Vehicle: ${latestKey.friendlyName.ifEmpty { "Digital Key" }}"
            tvKeyState.text = "Status: ${latestKey.core.keyState.name}"
            tvAccountId.text = "Linked Account: ${latestKey.accountID ?: "Device Local"}"
            
            latestKey.core.carMetadata?.let {
                tvMetadataBrand.text = "Brand: ${it.brandName} ${it.modelName}"
                tvMetadataPlate.text = "Plate: ${it.licensePlate}"
                tvMetadataColor.text = "Color: ${it.color}"
            }

            val color = when (latestKey.core.keyState) {
                KeyState.ACTIVE -> {
                    setActionsEnabled(true)
                    0xFF4CAF50.toInt()
                }
                KeyState.PROVISIONING -> {
                    setActionsEnabled(false)
                    0xFFFFC107.toInt()
                }
                else -> {
                    setActionsEnabled(false)
                    0xFFF44336.toInt()
                }
            }
            tvKeyState.setTextColor(color)
        } else {
            resetUIToEmptyState()
        }
    }

    private fun setActionsEnabled(enabled: Boolean) {
        btnUnlock.isEnabled = enabled
        btnLock.isEnabled = enabled
        btnStart.isEnabled = enabled
    }

    private fun resetUIToEmptyState() {
        tvKeyName.text = "Vehicle: Not Paired"
        tvKeyState.text = "Status: NO_KEY"
        tvAccountId.text = "Linked Account: None"
        tvMetadataBrand.text = "Brand: --"
        tvMetadataPlate.text = "Plate: --"
        tvMetadataColor.text = "Color: --"
        tvKeyState.setTextColor(0xFF9E9E9E.toInt())
        setActionsEnabled(false)
    }

    override fun onResume() {
        super.onResume()
        refreshKeyStateUI()
    }

    override fun onDestroy() {
        super.onDestroy()
        unregisterReceiver(nfcReceiver)
    }
}
