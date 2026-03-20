package com.example.a100_basiccrypto

import android.content.*
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.widget.Button
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import com.example.a100_basiccrypto.shared.command.MessageConstants.INS_LOCK
import com.example.a100_basiccrypto.shared.command.MessageConstants.INS_STOP_ENGINE
import com.example.a100_basiccrypto.shared.command.MessageConstants.INS_UNLOCK
import com.example.a100_basiccrypto.shared.command.MessageConstants.AUTH_INIT
import com.example.a100_basiccrypto.shared.command.MessageConstants.FINAL_COMMIT
import com.example.a100_basiccrypto.shared.command.SharingConstants
import com.example.a100_basiccrypto.digitalkey.core.SharingViewModel
import com.example.a100_basiccrypto.digitalkey.crypto.CryptoUtils.toHex
import com.example.a100_basiccrypto.digitalkey.crypto.DilithiumIdentityCryptoImpl
import com.example.a100_basiccrypto.digitalkey.nfc.MyHostApduService
import com.example.a100_basiccrypto.digitalkey.storage.SecureKeyStorageManager
import com.google.android.material.bottomsheet.BottomSheetDialog
import kotlinx.coroutines.launch

class ControlActivity : AppCompatActivity() {

    private lateinit var tvName: TextView
    private lateinit var tvPlate: TextView
    private lateinit var tvConnectionStatus: TextView
    private lateinit var viewStatusDot: View
    private lateinit var loadingOverlay: View
    
    private var authDialog: AlertDialog? = null
    private val handler = Handler(Looper.getMainLooper())
    
    private val storageManager by lazy { SecureKeyStorageManager(this) }
    private var currentKey: DigitalKeyRecord? = null

    private lateinit var sharingViewModel: SharingViewModel

    private val nfcResultReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            when (intent?.action) {
                MyHostApduService.ACTION_NFC_RESULT -> {
                    val actionName = intent.getStringExtra("action_name") ?: "NFC Action"
                    val isSuccess = intent.getBooleanExtra("is_success", false)
                    showActionResponseDialog(actionName, isSuccess)
                }
                MyHostApduService.LOG_ACTION -> {
                    val message = intent.getStringExtra("log_message") ?: ""
                    handleInternalLogs(message)
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_control)

        sharingViewModel = ViewModelProvider(this, object : ViewModelProvider.Factory {
            override fun <T : ViewModel> create(modelClass: Class<T>): T {
                return SharingViewModel(DilithiumIdentityCryptoImpl(), storageManager) as T
            }
        })[SharingViewModel::class.java]

        setupToolbar()
        
        tvName = findViewById(R.id.tv_detail_name)
        tvPlate = findViewById(R.id.tv_detail_plate)
        tvConnectionStatus = findViewById(R.id.tv_connection_status)
        viewStatusDot = findViewById(R.id.view_status_dot)
        loadingOverlay = findViewById(R.id.loading_overlay)

        val keyId = intent.getByteArrayExtra("KEY_ID")
        currentKey = storageManager.getAllKeys().find { it.core.keyID?.contentEquals(keyId) == true }

        if (currentKey == null) {
            finish()
            return
        }

        displayKeyInfo()

        // Controls
        findViewById<View>(R.id.btn_control_unlock).setOnClickListener { performAction(INS_UNLOCK, "UNLOCK") }
        findViewById<View>(R.id.btn_control_lock).setOnClickListener { performAction(INS_LOCK, "LOCK") }
        findViewById<View>(R.id.btn_control_start).setOnClickListener { performAction(INS_STOP_ENGINE, "STOP ENGINE") }
        
        findViewById<View>(R.id.btn_control_trunk).setOnClickListener { 
            performAction(0x03, "TRUNK")
        }

        findViewById<View>(R.id.btn_ekeys).setOnClickListener { 
            val intent = Intent(this, EKeyManagerActivity::class.java)
            intent.putExtra("KEY_ID", currentKey?.core?.keyID)
            startActivity(intent)
        }
        
        findViewById<View>(R.id.btn_settings).setOnClickListener { 
            val intent = Intent(this, SettingsActivity::class.java)
            intent.putExtra("KEY_ID", currentKey?.core?.keyID)
            startActivity(intent)
        }

        observeViewModel()
    }

    private fun handleInternalLogs(message: String) {
        // Show re-authentication dialog when Standard Transaction starts
        if (message.contains("STD: Phase 1") || message.contains("Reader Connected")) {
            showAuthenticatingDialog()
        }
        // Hide when complete
        if (message.contains("Transaction Finalized") || message.contains("Session Timeout")) {
            authDialog?.dismiss()
        }
    }

    private fun showAuthenticatingDialog() {
        if (authDialog?.isShowing == true) return
        
        val builder = AlertDialog.Builder(this)
        val view = layoutInflater.inflate(R.layout.dialog_standard_authenticating, null)
        builder.setView(view)
        builder.setCancelable(false)
        authDialog = builder.create()
        authDialog?.window?.setBackgroundDrawableResource(android.R.color.transparent)
        authDialog?.show()
    }

    override fun onStart() {
        super.onStart()
        val filter = IntentFilter().apply {
            addAction(MyHostApduService.ACTION_NFC_RESULT)
            addAction(MyHostApduService.LOG_ACTION)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(nfcResultReceiver, filter, Context.RECEIVER_EXPORTED)
        } else {
            registerReceiver(nfcResultReceiver, filter)
        }
    }

    override fun onStop() {
        super.onStop()
        unregisterReceiver(nfcResultReceiver)
        authDialog?.dismiss()
    }

    private fun setupToolbar() {
        val toolbar = findViewById<Toolbar>(R.id.toolbar_control)
        toolbar.setNavigationOnClickListener { finish() }
    }

    private fun observeViewModel() {
        lifecycleScope.launch {
            sharingViewModel.uiState.collect { state ->
                when (state) {
                    is SharingViewModel.SharingUiState.ShareSuccess -> {
                        showInvitationResultDialog(state.code)
                        sharingViewModel.resetState()
                    }
                    is SharingViewModel.SharingUiState.Loading -> {
                        loadingOverlay.visibility = View.VISIBLE
                    }
                    else -> {
                        loadingOverlay.visibility = View.GONE
                    }
                }
            }
        }
    }

    private fun showInvitationResultDialog(code: String) {
        val dialog = BottomSheetDialog(this)
        val view = LayoutInflater.from(this).inflate(R.layout.dialog_invitation_result, null)
        dialog.setContentView(view)
        view.findViewById<TextView>(R.id.tv_invitation_code_display).text = code.chunked(3).joinToString(" ")
        view.findViewById<Button>(R.id.btn_done_sharing).setOnClickListener { dialog.dismiss() }
        dialog.show()
    }

    private fun displayKeyInfo() {
        currentKey?.let {
            tvName.text = if (it.friendlyName.isNotEmpty()) it.friendlyName else (it.core.carMetadata?.modelName ?: "Digital Key")
            tvPlate.text = it.core.carMetadata?.licensePlate ?: "NO PLATE"
            tvConnectionStatus.text = "Connected (${it.core.role})"
            viewStatusDot.setBackgroundResource(R.drawable.shape_dot_green)
        }
    }

    private fun performAction(ins: Byte, actionName: String) {
        // This is a local simulation for UI feedback
        // The real NFC trigger comes from the Reader
        Toast.makeText(this, "Simulating $actionName... Tap NFC Reader", Toast.LENGTH_SHORT).show()
    }

    private fun showActionResponseDialog(action: String, isSuccess: Boolean) {
        authDialog?.dismiss() // Ensure auth dialog is gone if it was there
        
        val dialog = BottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.dialog_action_result, null)
        dialog.setContentView(view)

        val ivIcon = view.findViewById<ImageView>(R.id.iv_result_icon)
        val tvTitle = view.findViewById<TextView>(R.id.tv_result_title)
        val tvMessage = view.findViewById<TextView>(R.id.tv_result_message)
        val btnOk = view.findViewById<Button>(R.id.btn_result_ok)

        if (isSuccess) {
            ivIcon.setImageResource(android.R.drawable.checkbox_on_background)
            ivIcon.setColorFilter(getColor(R.color.success_green))
            tvTitle.text = "Success"
            tvTitle.setTextColor(getColor(R.color.success_green))
            tvMessage.text = "Command [$action] executed successfully."
        } else {
            ivIcon.setImageResource(android.R.drawable.ic_delete)
            ivIcon.setColorFilter(getColor(R.color.error_red))
            tvTitle.text = "Action Denied"
            tvTitle.setTextColor(getColor(R.color.error_red))
            tvMessage.text = "Command [$action] failed.\nSystem desynchronized or permission denied."
        }

        // Auto-dismiss after 3 seconds
        val dismissRunnable = Runnable { if (dialog.isShowing) dialog.dismiss() }
        handler.postDelayed(dismissRunnable, 3000)

        btnOk.setOnClickListener { 
            handler.removeCallbacks(dismissRunnable)
            dialog.dismiss() 
        }

        dialog.show()
    }
}
