package com.example.a100_basiccrypto.ui.keycontrol

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.widget.Button
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.core.content.ContextCompat
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import com.example.a100_basiccrypto.MainApplication
import com.example.a100_basiccrypto.R
import com.example.a100_basiccrypto.digitalkey.ble.BleProvider
import com.example.a100_basiccrypto.digitalkey.nfc.MyHostApduService
import com.example.a100_basiccrypto.digitalkey.transactions.FastTransactionClient
import com.example.a100_basiccrypto.digitalkey.transactions.StandardTransactionClient
import com.example.a100_basiccrypto.shared.command.MessageConstants.Class
import com.example.a100_basiccrypto.shared.command.MessageConstants.Fast
import com.example.a100_basiccrypto.shared.command.MessageConstants.Status
import com.example.a100_basiccrypto.shared.model.*
import com.google.android.material.bottomsheet.BottomSheetDialog
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * ControlActivity - Manages BLE Active control flow and Hybrid Security Recovery (HSR).
 */
class ControlActivity : AppCompatActivity() {

    private lateinit var tvName: TextView
    private lateinit var tvPlate: TextView
    private lateinit var tvConnectionStatus: TextView
    private lateinit var viewStatusDot: View
    private lateinit var loadingOverlay: View
    
    private val container by lazy { (application as MainApplication).container }
    private val storageManager by lazy { container.storageManager }
    private val authManager by lazy { container.authManager }
    private var currentKeyID: ByteArray? = null

    private lateinit var sharingViewModel: SharingViewModel
    private lateinit var fastTxClient: FastTransactionClient
    private lateinit var standardTxClient: StandardTransactionClient

    private val bleStatusListener: (String) -> Unit = { message ->
        runOnUiThread {
            updateBleUi(message)
        }
    }

    private val nfcResultReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val actionName = intent?.getStringExtra("action_name") ?: "Action"
            val isSuccess = intent?.getBooleanExtra("is_success", false) ?: false
            
            runOnUiThread {
                loadingOverlay.visibility = View.GONE
                val message = if (isSuccess) 
                    "NFC $actionName executed successfully." 
                else 
                    "NFC $actionName failed. Please try again."
                showActionResultDialog(isSuccess, message)
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_control)

        sharingViewModel = ViewModelProvider(this, object : ViewModelProvider.Factory {
            override fun <T : ViewModel> create(modelClass: java.lang.Class<T>): T {
                @Suppress("UNCHECKED_CAST")
                return SharingViewModel(
                    container.identityCrypto, 
                    storageManager,
                    authManager,
                    container.authRepository,
                    container.keyRepository
                ) as T
            }
        })[SharingViewModel::class.java]

        fastTxClient = FastTransactionClient(storageManager) { 
            Log.d("ControlActivity", "FastTx: $it") 
        }
        
        standardTxClient = StandardTransactionClient(storageManager, container.identityCrypto) {
            Log.d("ControlActivity", "StandardTx: $it")
        }

        initViews()
        setupToolbar()

        currentKeyID = intent.getByteArrayExtra("KEY_ID")
        if (currentKeyID == null) {
            finish()
            return
        }

        displayInitialInfo()
        setupActionListeners()
        observeViewModel()

        // Register NFC Result receiver
        val nfcFilter = IntentFilter(MyHostApduService.ACTION_NFC_RESULT)
        registerReceiver(nfcResultReceiver, nfcFilter, RECEIVER_EXPORTED)
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
            executeActionWithHsr(Class.FAST_ACTION, Fast.INS_UNLOCK) 
        }
        findViewById<View>(R.id.btn_control_lock).setOnClickListener { 
            executeActionWithHsr(Class.FAST_ACTION, Fast.INS_LOCK) 
        }
        findViewById<View>(R.id.btn_control_stop).setOnClickListener {
            executeActionWithHsr(Class.ENGINE_OP, Fast.INS_STOP_ENGINE)
        }
        findViewById<View>(R.id.btn_control_trunk).setOnClickListener { 
            executeActionWithHsr(Class.FAST_ACTION, Fast.INS_OPEN_TRUNK) 
        }

        findViewById<View>(R.id.btn_car_info).setOnClickListener {
            // Trigger immediate sync and switch to fast polling when opening info
            BleProvider.triggerImmediateSync()
            showVehicleInfoDialog()
        }

        findViewById<View>(R.id.btn_ekeys).setOnClickListener { 
            val intent = Intent(this, EKeyManagerActivity::class.java)
            intent.putExtra("KEY_ID", currentKeyID)
            startActivity(intent)
        }
        
        findViewById<View>(R.id.btn_settings).setOnClickListener { 
            val intent = Intent(this, SettingsActivity::class.java)
            intent.putExtra("KEY_ID", currentKeyID)
            startActivity(intent)
        }
    }

    /**
     * Implementation of Hybrid Security Recovery (HSR).
     * Automatically attempts BLE Standard Sync on security failures (Replay/Auth error).
     */
    private fun executeActionWithHsr(msgClass: Byte, targetIns: Byte) {
        val keyID = currentKeyID ?: return
        
        val bleManager = BleProvider.getManager()
        val bleTransport = BleProvider.getTransport()

        if (bleManager == null || bleTransport == null || !bleManager.isConnected()) {
            Toast.makeText(this, "BLE not connected.", Toast.LENGTH_SHORT).show()
            return
        }

        lifecycleScope.launch {
            loadingOverlay.visibility = View.VISIBLE
            
            // 1. First attempt: Fast Transaction
            val status = fastTxClient.execute(
                transport = bleTransport,
                keyID = keyID,
                msgClass = msgClass,
                targetIns = targetIns
            )

            when (status) {
                Status.SUCCESS -> {
                    loadingOverlay.visibility = View.GONE
                    showActionResultDialog(true, "Action executed successfully over BLE.")
                }
                
                Status.ERR_REPLAY_ATTACK, Status.ERR_AUTH_FAIL -> {
                    // 2. SECURITY FAILURE: Initiate Remote Recovery over BLE
                    Log.w("HSR", "Security issue detected (Status: 0x%02X). Starting BLE Recovery...".format(status))
                    
                    // Standard Transaction rotates keys and resets counter
                    val syncSuccess = standardTxClient.executeSync(bleTransport, keyID)

                    if (syncSuccess) {
                        Log.i("HSR", "Remote Recovery Successful. Retrying command...")
                        delay(1000) // Brief pause for persistence synchronization

                        // 3. RETRY: Execute the original command with fresh credentials
                        val retryStatus = fastTxClient.execute(
                            transport = bleTransport,
                            keyID = keyID,
                            msgClass = msgClass,
                            targetIns = targetIns
                        )

                        loadingOverlay.visibility = View.GONE
                        if (retryStatus == Status.SUCCESS) {
                            showActionResultDialog(true, "Security Restored & Action Executed!")
                        } else {
                            showActionResultDialog(false, "Security Restored, but command failed (0x%02X).".format(retryStatus))
                        }
                    } else {
                        // 4. REMOTE RECOVERY FAILED: Fallback to Physical NFC Tap
                        loadingOverlay.visibility = View.GONE
                        Log.e("HSR", "BLE Recovery failed. NFC interaction required.")
                        showNfcRecoveryDialog()
                    }
                }
                
                else -> {
                    loadingOverlay.visibility = View.GONE
                    showActionResultDialog(false, "Vehicle returned error code: 0x%02X".format(status))
                }
            }
        }
    }

    private fun showActionResultDialog(success: Boolean, message: String) {
        val dialog = BottomSheetDialog(this)
        val view = LayoutInflater.from(this).inflate(R.layout.dialog_action_result, null)
        dialog.setContentView(view)

        val ivIcon = view.findViewById<ImageView>(R.id.iv_result_icon)
        val tvTitle = view.findViewById<TextView>(R.id.tv_result_title)
        val tvMessage = view.findViewById<TextView>(R.id.tv_result_message)
        val btnClose = view.findViewById<Button>(R.id.btn_result_ok)

        if (success) {
            ivIcon.setImageResource(android.R.drawable.checkbox_on_background)
            ivIcon.setColorFilter(ContextCompat.getColor(this, R.color.success_green))
            tvTitle.text = "Success"
            tvTitle.setTextColor(ContextCompat.getColor(this, R.color.success_green))
        } else {
            ivIcon.setImageResource(android.R.drawable.ic_delete)
            ivIcon.setColorFilter(ContextCompat.getColor(this, R.color.error_red))
            tvTitle.text = "Action Failed"
            tvTitle.setTextColor(ContextCompat.getColor(this, R.color.error_red))
        }

        tvMessage.text = message
        btnClose.setOnClickListener { dialog.dismiss() }
        
        dialog.show()
    }

    private fun showNfcRecoveryDialog() {
        AlertDialog.Builder(this)
            .setTitle("Security Sync Required")
            .setMessage("For your protection, a secure physical synchronization is needed. Please tap your phone to the vehicle's door handle.")
            .setPositiveButton("I UNDERSTAND", null)
            .setCancelable(false)
            .show()
    }

    private fun showVehicleInfoDialog() {
        val keyID = currentKeyID ?: return
        val initialRecord = storageManager.getDigitalKey(keyID) ?: return
        
        val dialog = BottomSheetDialog(this)
        val dialogView = LayoutInflater.from(this).inflate(R.layout.dialog_vehicle_info, null)
        dialog.setContentView(dialogView)

        dialogView.findViewById<TextView>(R.id.tv_dialog_vehicle_name).text = 
            initialRecord.friendlyName.ifEmpty { initialRecord.carMetadata?.modelName ?: "Vehicle" }
        dialogView.findViewById<TextView>(R.id.tv_dialog_vehicle_plate).text = 
            initialRecord.carMetadata?.licensePlate ?: "N/A"

        val telemetryListener: (VehicleStatus) -> Unit = { status ->
            runOnUiThread {
                refreshDialogUi(dialogView, status)
            }
        }

        initialRecord.vehicleStatus?.let { refreshDialogUi(dialogView, it) } ?: run {
            Toast.makeText(this, "Waiting for sync...", Toast.LENGTH_SHORT).show()
        }

        // Enable fast polling while dialog is open
        BleProvider.setFastPolling(true)
        BleProvider.addTelemetryListener(telemetryListener)
        
        dialog.setOnDismissListener { 
            BleProvider.removeTelemetryListener(telemetryListener)
            // Revert to normal polling when dialog closed
            BleProvider.setFastPolling(false)
        }

        dialogView.findViewById<Button>(R.id.btn_close_status).setOnClickListener { dialog.dismiss() }
        dialog.show()
    }

    private fun refreshDialogUi(view: View, status: VehicleStatus) {
        val tvEngine = view.findViewById<TextView>(R.id.tv_status_engine)
        val ivEngine = view.findViewById<ImageView>(R.id.iv_engine_icon)
        if (status.engineState == EngineState.RUNNING) {
            tvEngine.text = "Running"
            tvEngine.setTextColor(ContextCompat.getColor(this, R.color.success_green))
            ivEngine.setColorFilter(ContextCompat.getColor(this, R.color.success_green))
        } else {
            tvEngine.text = "Stopped"
            tvEngine.setTextColor(ContextCompat.getColor(this, R.color.white))
            ivEngine.setColorFilter(ContextCompat.getColor(this, R.color.gray_text))
        }

        view.findViewById<TextView>(R.id.tv_status_temp).text = getString(R.string.temp_format, status.temperature)
        view.findViewById<TextView>(R.id.tv_status_battery).text = getString(R.string.battery_format, status.batteryLevel)
        view.findViewById<TextView>(R.id.tv_status_odometer).text = getString(R.string.odo_format, status.odometer)

        val tvTrunk = view.findViewById<TextView>(R.id.tv_status_trunk)
        val ivTrunk = view.findViewById<ImageView>(R.id.iv_trunk_icon)
        if (status.trunkState == TrunkState.OPEN) {
            tvTrunk.text = "Open"
            tvTrunk.setTextColor(ContextCompat.getColor(this, R.color.primary_blue))
            ivTrunk.setColorFilter(ContextCompat.getColor(this, R.color.primary_blue))
        } else {
            tvTrunk.text = "Closed"
            tvTrunk.setTextColor(ContextCompat.getColor(this, R.color.white))
            ivTrunk.setColorFilter(ContextCompat.getColor(this, R.color.gray_text))
        }

        updateDoorStatusUi(view, R.id.tv_status_door_fl, R.id.iv_door_fl_icon, status.doorStates[DoorLocation.FRONT_LEFT])
        updateDoorStatusUi(view, R.id.tv_status_door_fr, R.id.iv_door_fr_icon, status.doorStates[DoorLocation.FRONT_RIGHT])
        updateDoorStatusUi(view, R.id.tv_status_door_rl, R.id.iv_door_rl_icon, status.doorStates[DoorLocation.REAR_LEFT])
        updateDoorStatusUi(view, R.id.tv_status_door_rr, R.id.iv_door_rr_icon, status.doorStates[DoorLocation.REAR_RIGHT])
    }

    private fun updateDoorStatusUi(parent: View, tvId: Int, ivId: Int, state: DoorState?) {
        val tv = parent.findViewById<TextView>(tvId)
        val iv = parent.findViewById<ImageView>(ivId)
        if (state == DoorState.LOCKED) {
            tv.text = "Locked"
            tv.setTextColor(ContextCompat.getColor(this, R.color.white))
            iv.setImageResource(android.R.drawable.ic_lock_lock)
            iv.setColorFilter(ContextCompat.getColor(this, R.color.gray_text))
        } else {
            tv.text = "Unlocked"
            tv.setTextColor(ContextCompat.getColor(this, R.color.error_red))
            iv.setImageResource(android.R.drawable.ic_lock_idle_lock)
            iv.setColorFilter(ContextCompat.getColor(this, R.color.error_red))
        }
    }

    private fun updateBleUi(status: String) {
        // Handle nullable BleCentralManager here
        val isConnected = BleProvider.getManager()?.isConnected() == true
        
        if (isConnected) {
            viewStatusDot.setBackgroundResource(R.drawable.shape_dot_green)
            tvConnectionStatus.text = "Connected"
        } else if (status.contains("Searching") || status.contains("Initializing")) {
            viewStatusDot.setBackgroundResource(R.drawable.shape_dot_orange)
            tvConnectionStatus.text = "Searching..."
        } else {
            viewStatusDot.setBackgroundResource(R.drawable.shape_dot_grey)
            tvConnectionStatus.text = "Disconnected"
        }
    }

    override fun onResume() {
        super.onResume()
        BleProvider.addStatusListener(bleStatusListener)
        displayInitialInfo()
    }

    override fun onPause() {
        super.onPause()
        BleProvider.removeStatusListener(bleStatusListener)
    }

    override fun onDestroy() {
        super.onDestroy()
        unregisterReceiver(nfcResultReceiver)
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

    private fun displayInitialInfo() {
        val record = storageManager.getAllKeys().find { it.core.keyID?.contentEquals(currentKeyID) == true }
        record?.let {
            tvName.text = it.friendlyName.ifEmpty { it.carMetadata?.modelName ?: "Digital Key" }
            tvPlate.text = it.carMetadata?.licensePlate ?: "NO PLATE"
            updateBleUi("Initial check")
        }
    }
}
