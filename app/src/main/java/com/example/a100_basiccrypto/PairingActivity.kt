package com.example.a100_basiccrypto

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.example.a100_basiccrypto.digitalkey.nfc.MyHostApduService
import com.example.a100_basiccrypto.digitalkey.storage.PasswordManager

class PairingActivity : AppCompatActivity() {

    private lateinit var tvLog: TextView
    private lateinit var etPassword: EditText
    private lateinit var btnStart: Button

    private val nfcReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val message = intent?.getStringExtra("log_message")
            if (message != null) {
                updateLog(message)
                if (message.contains("Pairing Complete")) {
                    MyHostApduService.isPairingModeEnabled = false // Disable after success
                    Toast.makeText(this@PairingActivity, "Success! Returning home...", Toast.LENGTH_LONG).show()
                    Handler(Looper.getMainLooper()).postDelayed({
                        finish()
                    }, 2000)
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_pairing)

        tvLog = findViewById(R.id.tv_pairing_log)
        etPassword = findViewById(R.id.et_pairing_password)
        btnStart = findViewById(R.id.btn_start_pairing)

        etPassword.setText(PasswordManager.getPassword(this))

        btnStart.setOnClickListener {
            val pwd = etPassword.text.toString()
            if (pwd.isNotEmpty()) {
                PasswordManager.setPassword(this, pwd)
                
                // ENABLE pairing mode when user confirms
                MyHostApduService.isPairingModeEnabled = true
                
                updateLog("Pairing Mode ENABLED. Please tap NFC reader now.")
                Toast.makeText(this, "Ready to pair", Toast.LENGTH_SHORT).show()
            }
        }

        val filter = IntentFilter("com.example.a100_basiccrypto.LOG_ACTION")
        registerReceiver(nfcReceiver, filter, RECEIVER_EXPORTED)
    }

    override fun onResume() {
        super.onResume()
        // Optional: Reset state just in case
        // MyHostApduService.isPairingModeEnabled = false
    }

    private fun updateLog(message: String) {
        runOnUiThread {
            val currentText = tvLog.text.toString()
            tvLog.text = "[PAIRING] > $message\n$currentText"
        }
    }

    override fun onStop() {
        super.onStop()
        // Disable pairing mode if user leaves the screen
        MyHostApduService.isPairingModeEnabled = false
    }

    override fun onDestroy() {
        super.onDestroy()
        unregisterReceiver(nfcReceiver)
    }
}
