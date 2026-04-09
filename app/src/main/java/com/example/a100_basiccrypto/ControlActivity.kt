package com.example.a100_basiccrypto

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import com.example.a100_basiccrypto.digitalkey.core.SharingViewModel
import com.example.a100_basiccrypto.shared.crypto.DilithiumIdentityCryptoImpl
import com.example.a100_basiccrypto.digitalkey.storage.SecureKeyStorageManager
import com.example.a100_basiccrypto.digitalkey.transactions.FastTransactionClient
import com.example.a100_basiccrypto.digitalkey.ble.BleProvider
import com.example.a100_basiccrypto.shared.command.MessageConstants.Class
import com.example.a100_basiccrypto.shared.command.MessageConstants.Fast
import com.example.a100_basiccrypto.shared.command.MessageConstants.Status
import com.example.a100_basiccrypto.shared.link.LogicalFrame
import com.google.android.material.bottomsheet.BottomSheetDialog
import kotlinx.coroutines.launch

/**
 * ControlActivity manages the individual key details and sharing features.
 * Handles Active BLE Transactions while NFC remains Passive and Always-On.
 */
class ControlActivity : AppCompatActivity() {

    private lateinit var tvName: TextView
    private lateinit var tvPlate: TextView
    private lateinit var tvConnectionStatus: TextView
    private lateinit var viewStatusDot: View
    private lateinit var loadingOverlay: View
    
    private val storageManager by lazy { SecureKeyStorageManager(this) }
    private var currentKey: DigitalKeyRecord? = null

    private lateinit var sharingViewModel: SharingViewModel
    private lateinit var fastTxClient: FastTransactionClient

    private val bleStatusListener: (String) -> Unit = { message ->
        runOnUiThread {
            updateBleUi(message)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_control)

        sharingViewModel = ViewModelProvider(this, object : ViewModelProvider.Factory {
            override fun <T : ViewModel> create(modelClass: java.lang.Class<T>): T {
                @Suppress("UNCHECKED_CAST")
                return SharingViewModel(DilithiumIdentityCryptoImpl(), storageManager) as T
            }
        })[SharingViewModel::class.java]

        fastTxClient = FastTransactionClient(storageManager) { message ->
            runOnUiThread { Log.d("ControlActivity", "FastTx: $message") }
        }

        initViews()
        setupToolbar()

        val keyId = intent.getByteArrayExtra("KEY_ID")
        currentKey = storageManager.getAllKeys().find { it.core.keyID?.contentEquals(keyId) == true }

        if (currentKey == null) {
            finish()
            return
        }

        displayKeyInfo()
        setupActionListeners()
        observeViewModel()
    }

    private fun initViews() {
        tvName = findViewById(R.id.tv_detail_name)
        tvPlate = findViewById(R.id.tv_detail_plate)
        tvConnectionStatus = findViewById(R.id.tv_connection_status)
        viewStatusDot = findViewById(R.id.view_status_dot)
        loadingOverlay = findViewById(R.id.loading_overlay)
    }

    private fun setupToolbar() {
        val toolbar = findViewById<Toolbar>(R.id.toolbar_control)
        toolbar.setNavigationOnClickListener { finish() }
    }

    private fun setupActionListeners() {
        findViewById<View>(R.id.btn_control_unlock).setOnClickListener { 
            performFastAction(Class.FAST_ACTION, Fast.INS_UNLOCK) 
        }
        findViewById<View>(R.id.btn_control_lock).setOnClickListener { 
            performFastAction(Class.FAST_ACTION, Fast.INS_LOCK) 
        }
        findViewById<View>(R.id.btn_control_start).setOnClickListener { 
            performFastAction(Class.ENGINE_OP, Fast.INS_START_ENGINE) 
        }
        findViewById<View>(R.id.btn_control_trunk).setOnClickListener { 
            performFastAction(Class.FAST_ACTION, Fast.INS_OPEN_TRUNK) 
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
    }

    private fun performFastAction(msgClass: Byte, targetIns: Byte) {
        val record = currentKey ?: return
        
        if (!BleProvider.getManager().isConnected()) {
            Toast.makeText(this, "BLE not connected. Use NFC or wait.", Toast.LENGTH_SHORT).show()
            return
        }

        lifecycleScope.launch {
            try {
                loadingOverlay.visibility = View.VISIBLE
                
                val authPayload = fastTxClient.prepareActionRequest(record, targetIns)
                if (authPayload == null) {
                    Toast.makeText(this@ControlActivity, "Security Error: Key not active", Toast.LENGTH_SHORT).show()
                    loadingOverlay.visibility = View.GONE
                    return@launch
                }

                val frame = LogicalFrame(msgClass, targetIns, authPayload)
                val response = BleProvider.getTransport().exchange(frame)
                
                if (response.status == Status.SUCCESS) {
                    val success = fastTxClient.processCommitResponse(record, response.data)
                    if (success) {
                        Toast.makeText(this@ControlActivity, "Action Successful!", Toast.LENGTH_SHORT).show()
                    } else {
                        Toast.makeText(this@ControlActivity, "Vehicle rejected the action", Toast.LENGTH_SHORT).show()
                    }
                } else {
                    Toast.makeText(this@ControlActivity, "Transaction failed (Status: ${response.status})", Toast.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                Toast.makeText(this@ControlActivity, "Communication Error: ${e.message}", Toast.LENGTH_SHORT).show()
            } finally {
                loadingOverlay.visibility = View.GONE
            }
        }
    }

    private fun updateBleUi(status: String) {
        val isConnected = try { BleProvider.getManager().isConnected() } catch(e: Exception) { false }
        
        if (isConnected) {
            viewStatusDot.setBackgroundResource(R.drawable.shape_dot_green)
            tvConnectionStatus.text = "Connected (${currentKey?.core?.role})"
        } else if (status.contains("Searching") || status.contains("Initializing")) {
            viewStatusDot.setBackgroundResource(R.drawable.shape_dot_orange)
            tvConnectionStatus.text = "Searching..."
        } else {
            viewStatusDot.setBackgroundResource(R.drawable.shape_dot_grey)
            tvConnectionStatus.text = "Disconnected"
        }
        
        Log.d("ControlActivity", "BLE Status Update: $status (isConnected=$isConnected)")
    }

    override fun onResume() {
        super.onResume()
        BleProvider.addStatusListener(bleStatusListener)
    }

    override fun onPause() {
        super.onPause()
        BleProvider.removeStatusListener(bleStatusListener)
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
            tvName.text = it.friendlyName.ifEmpty { it.carMetadata?.modelName ?: "Digital Key" }
            tvPlate.text = it.carMetadata?.licensePlate ?: "NO PLATE"
            updateBleUi("Initial check")
        }
    }
}
