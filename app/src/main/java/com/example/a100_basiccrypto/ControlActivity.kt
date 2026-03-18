package com.example.a100_basiccrypto

import android.content.*
import android.os.Build
import android.os.Bundle
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
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.INS_LOCK
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.INS_STOP_ENGINE
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.INS_UNLOCK
import com.example.a100_basiccrypto.digitalkey.core.SharingConstants
import com.example.a100_basiccrypto.digitalkey.core.SharingViewModel
import com.example.a100_basiccrypto.digitalkey.crypto.CryptoUtils.toHex
import com.example.a100_basiccrypto.digitalkey.crypto.DilithiumIdentityCryptoImpl
import com.example.a100_basiccrypto.digitalkey.nfc.MyHostApduService
import com.example.a100_basiccrypto.digitalkey.storage.SecureKeyStorageManager
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.google.android.material.tabs.TabLayout
import kotlinx.coroutines.launch

class ControlActivity : AppCompatActivity() {

    private lateinit var tvName: TextView
    private lateinit var tvPlate: TextView
    private lateinit var tvConnectionStatus: TextView
    private lateinit var viewStatusDot: View
    private lateinit var loadingOverlay: View
    
    private val storageManager by lazy { SecureKeyStorageManager(this) }
    private var currentKey: DigitalKeyRecord? = null

    private lateinit var sharingViewModel: SharingViewModel

    private val nfcResultReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == MyHostApduService.ACTION_NFC_RESULT) {
                val actionName = intent.getStringExtra("action_name") ?: "NFC Action"
                val isSuccess = intent.getBooleanExtra("is_success", false)
                showActionResponseDialog(actionName, isSuccess)
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
        currentKey = storageManager.getAllKeys().find { it.keyID?.contentEquals(keyId) == true }

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

        // Navigation Menus
        findViewById<View>(R.id.btn_ekeys).setOnClickListener { 
            val intent = Intent(this, EKeyManagerActivity::class.java)
            intent.putExtra("KEY_ID", currentKey?.keyID)
            startActivity(intent)
        }
        
        findViewById<View>(R.id.btn_settings).setOnClickListener { 
            val intent = Intent(this, SettingsActivity::class.java)
            intent.putExtra("KEY_ID", currentKey?.keyID)
            startActivity(intent)
        }

        findViewById<View>(R.id.btn_records).setOnClickListener {
            Toast.makeText(this, "Records coming soon", Toast.LENGTH_SHORT).show()
        }

        observeViewModel()
    }

    override fun onStart() {
        super.onStart()
        val filter = IntentFilter(MyHostApduService.ACTION_NFC_RESULT)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(nfcResultReceiver, filter, Context.RECEIVER_EXPORTED)
        } else {
            registerReceiver(nfcResultReceiver, filter)
        }
    }

    override fun onStop() {
        super.onStop()
        unregisterReceiver(nfcResultReceiver)
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
            tvName.text = if (it.friendlyName.isNotEmpty()) it.friendlyName else (it.carMetadata?.modelName ?: "Digital Key")
            tvPlate.text = it.carMetadata?.licensePlate ?: "NO PLATE"
            tvConnectionStatus.text = "Connected (${it.role})"
            viewStatusDot.setBackgroundResource(R.drawable.shape_dot_green)
        }
    }

    private fun performAction(ins: Byte, actionName: String) {
        if (currentKey?.isAccessAllowedNow() == true) {
            showActionResponseDialog(actionName, true)
        } else {
            showActionResponseDialog(actionName, false)
        }
    }

    private fun showActionResponseDialog(action: String, isSuccess: Boolean) {
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
            tvMessage.text = "Command [$action] failed.\nYou may not have permission at this time."
        }

        btnOk.setOnClickListener { dialog.dismiss() }
        dialog.show()
    }
}
