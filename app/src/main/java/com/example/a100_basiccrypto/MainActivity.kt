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
import com.example.a100_basiccrypto.digitalkey.storage.PasswordManager
import com.example.a100_basiccrypto.digitalkey.storage.SecureKeyStorageManager

class MainActivity : AppCompatActivity() {

    private lateinit var tvLog: TextView
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
    
    private val storageManager by lazy { SecureKeyStorageManager(this) }

    private val nfcReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val message = intent?.getStringExtra("log_message")
            if (message != null) {
                updateLog(message)
                // Refresh UI whenever interaction happens
                runOnUiThread { refreshKeyStateUI() }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Initialize Primary Info Views
        tvLog = findViewById(R.id.tv_log)
        tvKeyName = findViewById(R.id.tv_key_name)
        tvKeyState = findViewById(R.id.tv_key_state)
        tvAccountId = findViewById(R.id.tv_account_id)
        
        // Initialize Metadata Views
        tvMetadataBrand = findViewById(R.id.tv_metadata_brand)
        tvMetadataPlate = findViewById(R.id.tv_metadata_plate)
        tvMetadataColor = findViewById(R.id.tv_metadata_color)
        
        // Initialize Action Buttons
        btnUnlock = findViewById(R.id.btn_unlock)
        btnLock = findViewById(R.id.btn_lock)
        btnStart = findViewById(R.id.btn_start)
        
        // Initialize Setup Views
        btnSavePassword = findViewById(R.id.btn_save_password)
        etPairingPassword = findViewById(R.id.et_pairing_password)

        updateLog("System Initialized. Ready for secure transactions.")
        
        // Load existing password
        etPairingPassword.setText(PasswordManager.getPassword(this))
        
        refreshKeyStateUI()

        // Handle Password Saving
        btnSavePassword.setOnClickListener {
            val pairingPassword = etPairingPassword.text.toString()
            if (pairingPassword.isNotEmpty()) {
                PasswordManager.setPassword(this, pairingPassword)
                Toast.makeText(this, "Credentials Updated", Toast.LENGTH_SHORT).show()
                updateLog("Pairing credentials updated in secure vault.")
            } else {
                Toast.makeText(this, "Entry cannot be empty", Toast.LENGTH_SHORT).show()
            }
        }

        // Register Receiver for NFC logs
        val filter = IntentFilter("com.example.a100_basiccrypto.LOG_ACTION")
        registerReceiver(nfcReceiver, filter, RECEIVER_EXPORTED)
    }

    private fun refreshKeyStateUI() {
        val keys = storageManager.getAllKeys()
        val latestKey = keys.lastOrNull()

        if (latestKey != null) {
            tvKeyName.text = "Vehicle: ${latestKey.friendlyName.ifEmpty { "Digital Key" }}"
            tvKeyState.text = "Status: ${latestKey.keyState.name}"
            tvAccountId.text = "Linked Account: ${latestKey.accountID ?: "Device Local"}"
            
            // Populate Metadata
            latestKey.carMetadata?.let {
                tvMetadataBrand.text = "Brand: ${it.brandName} ${it.modelName}"
                tvMetadataPlate.text = "Plate: ${it.licensePlate}"
                tvMetadataColor.text = "Color: ${it.color}"
            }

            // State-based Styling & Permissions
            val color = when (latestKey.keyState.name) {
                "ACTIVE" -> {
                    setActionsEnabled(true)
                    0xFF4CAF50.toInt() // Material Green
                }
                "PROVISIONING" -> {
                    setActionsEnabled(false)
                    0xFFFFC107.toInt() // Material Amber
                }
                else -> {
                    setActionsEnabled(false)
                    0xFFF44336.toInt() // Material Red
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
        tvKeyState.setTextColor(0xFF9E9E9E.toInt()) // Gray
        setActionsEnabled(false)
    }

    private fun updateLog(message: String) {
        val currentText = tvLog.text.toString()
        val newLog = "\n[TERMINAL] > $message\n$currentText"
        tvLog.text = newLog
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
