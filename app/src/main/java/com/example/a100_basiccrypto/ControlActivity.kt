package com.example.a100_basiccrypto

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.INS_LOCK
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.INS_START_ENGINE
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.INS_UNLOCK
import com.example.a100_basiccrypto.digitalkey.storage.SecureKeyStorageManager

class ControlActivity : AppCompatActivity() {

    private lateinit var tvLog: TextView
    private lateinit var tvName: TextView
    private lateinit var tvPlate: TextView
    private lateinit var tvStatus: TextView
    
    private val storageManager by lazy { SecureKeyStorageManager(this) }
    private var currentKey: DigitalKeyRecord? = null

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
        setContentView(R.layout.activity_control)

        tvLog = findViewById(R.id.tv_control_log)
        tvName = findViewById(R.id.tv_detail_name)
        tvPlate = findViewById(R.id.tv_detail_plate)
        tvStatus = findViewById(R.id.tv_detail_status)

        val keyId = intent.getByteArrayExtra("KEY_ID")
        currentKey = storageManager.getAllKeys().find { it.keyID?.contentEquals(keyId) == true }

        if (currentKey == null) {
            Toast.makeText(this, "Key not found", Toast.LENGTH_SHORT).show()
            finish()
            return
        }

        displayKeyInfo()

        findViewById<Button>(R.id.btn_control_unlock).setOnClickListener { performAction(INS_UNLOCK, "UNLOCK") }
        findViewById<Button>(R.id.btn_control_lock).setOnClickListener { performAction(INS_LOCK, "LOCK") }
        findViewById<Button>(R.id.btn_control_start).setOnClickListener { performAction(INS_START_ENGINE, "START ENGINE") }

        val filter = IntentFilter("com.example.a100_basiccrypto.LOG_ACTION")
        registerReceiver(nfcReceiver, filter, RECEIVER_EXPORTED)
    }

    private fun displayKeyInfo() {
        currentKey?.let {
            tvName.text = it.friendlyName
            tvPlate.text = "Plate: ${it.carMetadata?.licensePlate ?: "--"}"
            tvStatus.text = "Status: ${it.keyState.name}"
        }
    }

    private fun performAction(ins: Byte, actionName: String) {
        currentKey?.let { key ->
            val nextCounter = key.transactionCounter + 1
            storageManager.updateTransactionCounter(key.keyID!!, nextCounter)
            
            updateLog("Manual Action: $actionName (Counter: $nextCounter)")
            updateLog("Success: Device updated state for ${key.friendlyName}")
            
            Toast.makeText(this, "$actionName Executed", Toast.LENGTH_SHORT).show()
        }
    }

    private fun updateLog(message: String) {
        runOnUiThread {
            val currentText = tvLog.text.toString()
            tvLog.text = "[CONTROL] > $message\n$currentText"
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        unregisterReceiver(nfcReceiver)
    }
}
