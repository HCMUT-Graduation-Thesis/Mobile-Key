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
import com.example.a100_basiccrypto.digitalkey.nfc.MyHostApduService
import com.example.a100_basiccrypto.digitalkey.storage.PasswordManager
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.google.android.material.progressindicator.CircularProgressIndicator
import com.google.android.material.textfield.TextInputEditText

class PairingActivity : AppCompatActivity() {

    private lateinit var etPassword: TextInputEditText
    private lateinit var btnStart: Button
    private var nfcDialog: BottomSheetDialog? = null
    
    // Dialog components
    private var tvPhaseTitle: TextView? = null
    private var tvPhaseStatus: TextView? = null
    private var progressIndicator: CircularProgressIndicator? = null
    private var ivSuccessIcon: ImageView? = null

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
        tvPhaseStatus?.text = "Redirecting to Home..."
        
        progressIndicator?.visibility = View.GONE
        ivSuccessIcon?.visibility = View.VISIBLE
        
        // Switch to HomeActivity immediately (small delay for visual feedback)
        Handler(Looper.getMainLooper()).postDelayed({
            if (nfcDialog?.isShowing == true) {
                nfcDialog?.dismiss()
            }
            
            val homeIntent = Intent(this, HomeActivity::class.java)
            homeIntent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
            startActivity(homeIntent)
            finish()
        }, 800)
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
