package com.example.a100_basiccrypto

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {

    private lateinit var tvLog: TextView

    private val nfcReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val message = intent?.getStringExtra("log_message")
            if (message != null) {
                updateLog(message)
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        tvLog = findViewById(R.id.tv_log)
        updateLog("Service started. Ready for NFC...")

        // Đăng ký Receiver để nhận log từ Service
        val filter = IntentFilter("com.example.a100_basiccrypto.LOG_ACTION")
        registerReceiver(nfcReceiver, filter, RECEIVER_EXPORTED)
    }

    private fun updateLog(message: String) {
        val currentText = tvLog.text.toString()
        val newLog = "\n> $message\n$currentText"
        tvLog.text = newLog
    }

    override fun onDestroy() {
        super.onDestroy()
        unregisterReceiver(nfcReceiver)
    }
}
