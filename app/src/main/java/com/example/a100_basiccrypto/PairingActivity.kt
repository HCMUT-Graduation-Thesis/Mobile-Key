package com.example.a100_basiccrypto

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import com.example.a100_basiccrypto.digitalkey.nfc.MyHostApduService
import com.example.a100_basiccrypto.digitalkey.storage.PasswordManager
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.google.android.material.textfield.TextInputEditText

class PairingActivity : AppCompatActivity() {

    private lateinit var tvLog: TextView
    private lateinit var etPassword: TextInputEditText
    private lateinit var btnStart: Button
    private lateinit var btnClearLog: View
    private var nfcDialog: BottomSheetDialog? = null

    private val nfcReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val message = intent?.getStringExtra("log_message")
            if (message != null) {
                // Auto-dismiss dialog when NFC activity starts
                if (nfcDialog?.isShowing == true) {
                    nfcDialog?.dismiss()
                }
                
                updateLog(message)
                
                if (message.contains("Pairing Complete")) {
                    MyHostApduService.isPairingModeEnabled = false
                    updateLog("SUCCESS: Owner Key Provisioned.")
                    Handler(Looper.getMainLooper()).postDelayed({
                        finish()
                    }, 2500)
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_pairing)

        setupUI()
        
        val filter = IntentFilter("com.example.a100_basiccrypto.LOG_ACTION")
        registerReceiver(nfcReceiver, filter, RECEIVER_EXPORTED)
        
        updateLog("System initialized. Ready for Pairing.")
    }

    private fun setupUI() {
        val toolbar = findViewById<Toolbar>(R.id.toolbar_pairing)
        setSupportActionBar(toolbar)
        toolbar.setNavigationOnClickListener { finish() }

        tvLog = findViewById(R.id.tv_pairing_log)
        etPassword = findViewById(R.id.et_pairing_password)
        btnStart = findViewById(R.id.btn_start_pairing)
        btnClearLog = findViewById(R.id.btn_clear_pairing_log)

        // Sync with Backend Password
        etPassword.setText(PasswordManager.getPassword(this))

        btnStart.setOnClickListener {
            val pwd = etPassword.text.toString()
            if (pwd.length < 8) {
                Toast.makeText(this, "Password must be at least 8 characters", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            // Save to Backend Storage
            PasswordManager.setPassword(this, pwd)
            
            // Enable Pairing Logic
            MyHostApduService.isPairingModeEnabled = true
            updateLog("PAIRING MODE: ENABLED (Awaiting NFC Tap)")
            
            showNfcPairingDialog()
        }

        btnClearLog.setOnClickListener {
            tvLog.text = "> Log cleared."
        }
    }

    private fun showNfcPairingDialog() {
        nfcDialog = BottomSheetDialog(this)
        val view = LayoutInflater.from(this).inflate(R.layout.dialog_nfc_pairing, null)
        nfcDialog?.setContentView(view)
        nfcDialog?.show()
        
        nfcDialog?.setOnDismissListener {
            // Optional: Handle if user cancels dialog
        }
    }

    private fun updateLog(message: String) {
        runOnUiThread {
            val currentText = tvLog.text.toString()
            val timestamp = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.getDefault()).format(java.util.Date())
            tvLog.text = "> [$timestamp] $message\n$currentText"
        }
    }

    override fun onStop() {
        super.onStop()
        MyHostApduService.isPairingModeEnabled = false
    }

    override fun onDestroy() {
        super.onDestroy()
        unregisterReceiver(nfcReceiver)
    }
}
