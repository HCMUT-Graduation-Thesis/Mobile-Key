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
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.example.a100_basiccrypto.digitalkey.core.AuthManager
import com.example.a100_basiccrypto.digitalkey.core.MockKeyServer
import com.example.a100_basiccrypto.digitalkey.nfc.MyHostApduService
import com.example.a100_basiccrypto.digitalkey.storage.PasswordManager
import com.example.a100_basiccrypto.digitalkey.storage.SecureKeyStorageManager
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.google.android.material.progressindicator.CircularProgressIndicator
import com.google.android.material.textfield.TextInputEditText
import kotlinx.coroutines.launch

class PairingActivity : AppCompatActivity() {

    private lateinit var etPassword: TextInputEditText
    private lateinit var btnStart: Button
    private var nfcDialog: BottomSheetDialog? = null
    
    // Dialog components
    private var tvPhaseTitle: TextView? = null
    private var tvPhaseStatus: TextView? = null
    private var progressIndicator: CircularProgressIndicator? = null
    private var ivSuccessIcon: ImageView? = null

    private val authManager by lazy { AuthManager(this) }
    private val storageManager by lazy { SecureKeyStorageManager(this) }

    private val nfcReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val message = intent?.getStringExtra("log_message")
            if (message != null) {
                updatePairingStatus(message)
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_pairing)

        setupUI()
        
        val filter = IntentFilter("com.example.a100_basiccrypto.LOG_ACTION")
        registerReceiver(nfcReceiver, filter, RECEIVER_EXPORTED)
    }

    private fun setupUI() {
        val toolbar = findViewById<Toolbar>(R.id.toolbar_pairing)
        setSupportActionBar(toolbar)
        toolbar.setNavigationOnClickListener { finish() }

        etPassword = findViewById(R.id.et_pairing_password)
        btnStart = findViewById(R.id.btn_start_pairing)

        etPassword.setText(PasswordManager.getPassword(this))

        btnStart.setOnClickListener {
            val pwd = etPassword.text.toString()
            if (pwd.length < 8) {
                Toast.makeText(this, "Password must be at least 8 characters", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            PasswordManager.setPassword(this, pwd)
            MyHostApduService.isPairingModeEnabled = true
            showNfcPairingDialog()
        }
    }

    private fun showNfcPairingDialog() {
        nfcDialog = BottomSheetDialog(this)
        val view = LayoutInflater.from(this).inflate(R.layout.dialog_nfc_pairing, null)
        
        tvPhaseTitle = view.findViewById(R.id.tv_phase_title)
        tvPhaseStatus = view.findViewById(R.id.tv_phase_status)
        progressIndicator = view.findViewById(R.id.cp_pairing_loading)
        ivSuccessIcon = view.findViewById(R.id.iv_pairing_success)
        
        nfcDialog?.setContentView(view)
        nfcDialog?.show()
        
        nfcDialog?.setOnDismissListener {
            MyHostApduService.isPairingModeEnabled = false
        }
    }

    private fun updatePairingStatus(message: String) {
        runOnUiThread {
            if (nfcDialog?.isShowing != true) return@runOnUiThread

            when {
                message.contains("Phase 1") -> {
                    tvPhaseTitle?.text = "Step 1: Security Handshake"
                    tvPhaseStatus?.text = "Establishing a secure post-quantum encrypted channel..."
                }
                message.contains("Phase 2") -> {
                    tvPhaseTitle?.text = "Step 2: Key Exchange"
                    tvPhaseStatus?.text = "Generating and exchanging digital identity keys..."
                }
                message.contains("Phase 3") -> {
                    tvPhaseTitle?.text = "Step 3: Verification"
                    tvPhaseStatus?.text = "Verifying vehicle authority and proof-of-possession..."
                }
                message.contains("Phase 4") -> {
                    handlePairingSuccess()
                }
            }
        }
    }

    private fun handlePairingSuccess() {
        MyHostApduService.isPairingModeEnabled = false
        
        // Immediate Success UI
        tvPhaseTitle?.text = "Pairing Successful!"
        tvPhaseTitle?.setTextColor(ContextCompat.getColor(this, R.color.success_green))
        tvPhaseStatus?.text = "Synchronizing with Cloud..."
        
        progressIndicator?.visibility = View.VISIBLE // Re-show loading for sync
        ivSuccessIcon?.visibility = View.GONE

        // 2. Sync to Cloud
        syncNewKeyToCloud()
    }

    private fun syncNewKeyToCloud() {
        val token = authManager.getAuthToken()
        val email = authManager.getUserEmail()
        
        if (token == null || email == null) {
            finishPairing()
            return
        }

        // Get the most recent key (the one we just paired)
        val allKeys = storageManager.getAllKeys()
        val latestKey = allKeys.maxByOrNull { it.core.validityStart } ?: run {
            finishPairing()
            return
        }

        // TAG THE KEY with the current logged-in user email
        latestKey.accountEmail = email
        storageManager.saveDigitalKey(latestKey)

        val keyIdHex = latestKey.core.keyID?.joinToString("") { "%02x".format(it) } ?: "unknown"
        val metadata = latestKey.carMetadata ?: com.example.a100_basiccrypto.shared.model.CarMetadata(
            modelName = "New Vehicle",
            licensePlate = "PENDING"
        )

        lifecycleScope.launch {
            val success = MockKeyServer.syncKeyToCloud(token, keyIdHex, metadata)
            if (success) {
                runOnUiThread { 
                    tvPhaseStatus?.text = "Cloud Sync Complete!"
                    progressIndicator?.visibility = View.GONE
                    ivSuccessIcon?.visibility = View.VISIBLE
                }
            } else {
                runOnUiThread { Toast.makeText(this@PairingActivity, "Cloud Sync Failed (Offline)", Toast.LENGTH_SHORT).show() }
            }
            
            // Brief delay for user to see the "Sync Complete" message
            Handler(Looper.getMainLooper()).postDelayed({ finishPairing() }, 1200)
        }
    }

    private fun finishPairing() {
        if (nfcDialog?.isShowing == true) {
            nfcDialog?.dismiss()
        }
        val homeIntent = Intent(this, HomeActivity::class.java)
        homeIntent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
        startActivity(homeIntent)
        finish()
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
