package com.example.a100_basiccrypto

import android.content.*
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.INS_LOCK
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.INS_START_ENGINE
import com.example.a100_basiccrypto.digitalkey.core.MessageConstants.INS_UNLOCK
import com.example.a100_basiccrypto.digitalkey.core.SharingConstants
import com.example.a100_basiccrypto.digitalkey.core.SharingViewModel
import com.example.a100_basiccrypto.digitalkey.crypto.CryptoUtils.toHex
import com.example.a100_basiccrypto.digitalkey.crypto.DilithiumIdentityCryptoImpl
import com.example.a100_basiccrypto.digitalkey.storage.IKeyStorageManager
import com.example.a100_basiccrypto.digitalkey.storage.SecureKeyStorageManager
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.google.android.material.button.MaterialButtonToggleGroup
import com.google.android.material.chip.Chip
import com.google.android.material.chip.ChipGroup
import kotlinx.coroutines.launch

class ControlActivity : AppCompatActivity() {

    private lateinit var tvLog: TextView
    private lateinit var tvName: TextView
    private lateinit var tvPlate: TextView
    private lateinit var tvStatus: TextView
    private lateinit var tvFastKey: TextView
    private lateinit var btnClearLog: Button
    
    private val storageManager by lazy { SecureKeyStorageManager(this) }
    private var currentKey: DigitalKeyRecord? = null

    private lateinit var sharingViewModel: SharingViewModel
    private var isReceiverRegistered = false

    private val nfcReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val message = intent?.getStringExtra("log_message")
            if (message != null) {
                updateLog(message)
                refreshKeyData()
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_control)

        // Init ViewModel
        sharingViewModel = ViewModelProvider(this, object : ViewModelProvider.Factory {
            override fun <T : ViewModel> create(modelClass: Class<T>): T {
                return SharingViewModel(DilithiumIdentityCryptoImpl(), storageManager) as T
            }
        })[SharingViewModel::class.java]

        tvLog = findViewById(R.id.tv_control_log)
        tvName = findViewById(R.id.tv_detail_name)
        tvPlate = findViewById(R.id.tv_detail_plate)
        tvStatus = findViewById(R.id.tv_detail_status)
        tvFastKey = findViewById(R.id.tv_detail_fastkey)
        btnClearLog = findViewById(R.id.btn_clear_control_log)

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
        
        findViewById<Button>(R.id.btn_control_share).setOnClickListener {
            showShareDialog()
        }

        btnClearLog.setOnClickListener {
            tvLog.text = ""
        }

        val filter = IntentFilter("com.example.a100_basiccrypto.LOG_ACTION")
        registerReceiver(nfcReceiver, filter, RECEIVER_EXPORTED)
        isReceiverRegistered = true

        observeViewModel()
    }

    private fun observeViewModel() {
        lifecycleScope.launch {
            sharingViewModel.uiState.collect { state ->
                if (state is SharingViewModel.SharingUiState.ShareSuccess) {
                    showResultDialog(state.code)
                    sharingViewModel.resetState()
                } else if (state is SharingViewModel.SharingUiState.Error) {
                    Toast.makeText(this@ControlActivity, state.message, Toast.LENGTH_SHORT).show()
                    sharingViewModel.resetState()
                }
            }
        }
    }

    private fun showShareDialog() {
        val dialog = BottomSheetDialog(this)
        val view = LayoutInflater.from(this).inflate(R.layout.dialog_share_key, null)
        dialog.setContentView(view)

        val tvInfo = view.findViewById<TextView>(R.id.tv_share_vehicle_info)
        tvInfo.text = "${currentKey?.friendlyName} • ${currentKey?.carMetadata?.licensePlate ?: "--"}"

        val btnGenerate = view.findViewById<Button>(R.id.btn_generate_invitation)
        val chipGroup = view.findViewById<ChipGroup>(R.id.cg_permissions)
        val toggleGroup = view.findViewById<MaterialButtonToggleGroup>(R.id.tg_validity)

        btnGenerate.setOnClickListener {
            var perms = 0
            if (view.findViewById<Chip>(R.id.chip_perm_unlock).isChecked) perms = perms or SharingConstants.PERM_UNLOCK
            if (view.findViewById<Chip>(R.id.chip_perm_lock).isChecked) perms = perms or SharingConstants.PERM_LOCK
            if (view.findViewById<Chip>(R.id.chip_perm_start).isChecked) perms = perms or SharingConstants.PERM_START
            if (view.findViewById<Chip>(R.id.chip_perm_trunk).isChecked) perms = perms or SharingConstants.PERM_TRUNK
            if (view.findViewById<Chip>(R.id.chip_perm_panic).isChecked) perms = perms or SharingConstants.PERM_PANIC

            val validityDays = when (toggleGroup.checkedButtonId) {
                R.id.btn_val_24h -> 1
                R.id.btn_val_30d -> 30
                else -> 7
            }

            sharingViewModel.shareKey(currentKey!!, perms, validityDays)
            dialog.dismiss()
        }

        dialog.show()
    }

    private fun showResultDialog(code: String) {
        val dialog = BottomSheetDialog(this)
        val view = LayoutInflater.from(this).inflate(R.layout.dialog_invitation_result, null)
        dialog.setContentView(view)

        view.findViewById<TextView>(R.id.tv_invitation_code_display).text = code.chunked(3).joinToString(" ")

        view.findViewById<Button>(R.id.btn_copy_code).setOnClickListener {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = ClipData.newPlainText("Invitation Code", code)
            clipboard.setPrimaryClip(clip)
            Toast.makeText(this, "Code copied to clipboard", Toast.LENGTH_SHORT).show()
        }

        view.findViewById<Button>(R.id.btn_share_code).setOnClickListener {
            val intent = Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_TEXT, "Here is your Digital Key invitation code: $code")
            }
            startActivity(Intent.createChooser(intent, "Share Invitation Code"))
        }

        view.findViewById<Button>(R.id.btn_done_sharing).setOnClickListener { dialog.dismiss() }

        dialog.show()
    }

    private fun refreshKeyData() {
        val keyId = currentKey?.keyID ?: return
        currentKey = storageManager.getAllKeys().find { it.keyID?.contentEquals(keyId) == true }
        runOnUiThread { displayKeyInfo() }
    }

    private fun displayKeyInfo() {
        currentKey?.let {
            tvName.text = it.friendlyName
            tvPlate.text = "Plate: ${it.carMetadata?.licensePlate ?: "--"}"
            tvStatus.text = "Status: ${it.keyState.name}"
            
            val fastKeyHex = it.fastAuthKey?.toHex()?.take(8) ?: "--"
            tvFastKey.text = "FastKey (Prefix): $fastKeyHex..."
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
        if (isReceiverRegistered) {
            unregisterReceiver(nfcReceiver)
            isReceiverRegistered = false
        }
    }
}
