package com.example.a100_basiccrypto

import android.os.Bundle
import android.view.View
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import com.example.a100_basiccrypto.digitalkey.crypto.CryptoUtils.toHex
import com.example.a100_basiccrypto.digitalkey.storage.SecureKeyStorageManager
import com.google.android.material.button.MaterialButton
import com.google.android.material.textfield.TextInputEditText

class SettingsActivity : AppCompatActivity() {

    private lateinit var etVehicleName: TextInputEditText
    private lateinit var tvKeyId: TextView
    private lateinit var tvModuleId: TextView
    private lateinit var btnUpdate: MaterialButton
    private lateinit var btnDelete: MaterialButton
    private lateinit var btnFactoryReset: MaterialButton

    private val storageManager by lazy { SecureKeyStorageManager(this) }
    private var currentKey: DigitalKeyRecord? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)

        val keyId = intent.getByteArrayExtra("KEY_ID")
        currentKey = storageManager.getAllKeys().find { it.keyID?.contentEquals(keyId) == true }

        if (currentKey == null) {
            finish()
            return
        }

        setupUI()
    }

    private fun setupUI() {
        val toolbar = findViewById<Toolbar>(R.id.toolbar_settings)
        setSupportActionBar(toolbar)
        toolbar.setNavigationOnClickListener { finish() }

        etVehicleName = findViewById(R.id.et_settings_vehicle_name)
        tvKeyId = findViewById(R.id.tv_settings_key_id)
        tvModuleId = findViewById(R.id.tv_settings_module_id)
        btnUpdate = findViewById(R.id.btn_settings_firmware_update)
        btnDelete = findViewById(R.id.btn_settings_delete_key)
        btnFactoryReset = findViewById(R.id.btn_settings_factory_reset)

        currentKey?.let {
            etVehicleName.setText(it.friendlyName.ifEmpty { it.carMetadata?.modelName ?: "Vehicle" })
            // Display full IDs instead of truncated versions
            tvKeyId.text = "KeyID: ${it.keyID?.toHex() ?: "N/A"}"
            tvModuleId.text = "ModuleID: ${it.moduleID?.toHex() ?: "N/A"}"
        }

        btnUpdate.setOnClickListener {
            Toast.makeText(this, "Executing UPDATE_FIRMWARE command...", Toast.LENGTH_SHORT).show()
        }

        btnDelete.setOnClickListener {
            showConfirmationDialog(
                "Delete Key",
                "This will run REVOKE_OWNER command. The key will be permanently removed from this device and the ESP32 module.",
                "Delete"
            ) {
                Toast.makeText(this, "Key Revoked Successfully", Toast.LENGTH_SHORT).show()
                finish()
            }
        }

        btnFactoryReset.setOnClickListener {
            showConfirmationDialog(
                "Factory Reset",
                "CRITICAL: This will wipe all data from the module. This action cannot be undone.",
                "Reset"
            ) {
                Toast.makeText(this, "Module Factory Reset Initiated", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun showConfirmationDialog(title: String, message: String, confirmText: String, onConfirm: () -> Unit) {
        AlertDialog.Builder(this)
            .setTitle(title)
            .setMessage(message)
            .setNegativeButton("Cancel", null)
            .setPositiveButton(confirmText) { _, _ -> onConfirm() }
            .create()
            .apply {
                show()
                getButton(AlertDialog.BUTTON_POSITIVE).setTextColor(getColor(R.color.error_red))
            }
    }
}
