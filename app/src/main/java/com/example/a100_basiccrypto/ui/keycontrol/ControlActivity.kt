package com.example.a100_basiccrypto.ui.keycontrol

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
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
import com.example.a100_basiccrypto.shared.command.MessageConstants.Class
import com.example.a100_basiccrypto.shared.command.MessageConstants.Fast
import com.example.a100_basiccrypto.shared.model.*
import com.google.android.material.bottomsheet.BottomSheetDialog
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

class ControlActivity : AppCompatActivity() {

    private lateinit var tvName: TextView
    private lateinit var tvPlate: TextView
    private lateinit var tvConnectionStatus: TextView
    private lateinit var viewStatusDot: View
    private lateinit var loadingOverlay: View
    
    private val container by lazy { (application as MainApplication).container }
    private lateinit var controlViewModel: ControlViewModel
    private lateinit var sharingViewModel: SharingViewModel
    private var currentKeyID: ByteArray? = null

    private val bleStatusListener: (String) -> Unit = { message ->
        runOnUiThread { updateBleUi(message) }
    }

    private val nfcResultReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val actionName = intent?.getStringExtra("action_name") ?: "Action"
            val isSuccess = intent?.getBooleanExtra("is_success", false) ?: false
            runOnUiThread {
                loadingOverlay.visibility = View.GONE
                showActionResultDialog(isSuccess, "NFC $actionName ${if (isSuccess) "success" else "failed"}.")
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_control)

        currentKeyID = intent.getByteArrayExtra("KEY_ID")
        if (currentKeyID == null) { finish(); return }

        initViewModels()
        initViews()
        setupToolbar()
        setupActionListeners()
        setupObservers()

        val nfcFilter = IntentFilter(MyHostApduService.ACTION_NFC_RESULT)
        registerReceiver(nfcResultReceiver, nfcFilter, RECEIVER_EXPORTED)
    }

    private fun initViewModels() {
        controlViewModel = ViewModelProvider(this, object : ViewModelProvider.Factory {
            override fun <T : ViewModel> create(modelClass: java.lang.Class<T>): T {
                @Suppress("UNCHECKED_CAST")
                return ControlViewModel(container.storageManager, container.identityCrypto) as T
            }
        })[ControlViewModel::class.java]

        sharingViewModel = ViewModelProvider(this, object : ViewModelProvider.Factory {
            override fun <T : ViewModel> create(modelClass: java.lang.Class<T>): T {
                @Suppress("UNCHECKED_CAST")
                return SharingViewModel(
                    container.identityCrypto, container.storageManager, container.authManager,
                    container.authRepository, container.keyRepository
                ) as T
            }
        })[SharingViewModel::class.java]
    }

    private fun setupObservers() {
        lifecycleScope.launch {
            controlViewModel.uiState.collectLatest { state ->
                loadingOverlay.visibility = if (state is ControlViewModel.ControlUiState.Loading) View.VISIBLE else View.GONE
            }
        }

        lifecycleScope.launch {
            controlViewModel.events.collectLatest { event ->
                when (event) {
                    is ControlViewModel.ControlEvent.ActionSuccess -> showActionResultDialog(true, event.message)
                    is ControlViewModel.ControlEvent.Error -> Toast.makeText(this@ControlActivity, event.message, Toast.LENGTH_SHORT).show()
                    is ControlViewModel.ControlEvent.ShowNfcRecovery -> showNfcRecoveryDialog()
                }
            }
        }

        lifecycleScope.launch {
            controlViewModel.vehicleStatus.collectLatest { status -> status?.let { refreshControlUi(it) } }
        }

        lifecycleScope.launch {
            sharingViewModel.uiState.collectLatest { state ->
                if (state is SharingViewModel.SharingUiState.ShareSuccess) {
                    showInvitationResultDialog(state.code)
                    sharingViewModel.resetState()
                }
            }
        }
    }

    private fun initViews() {
        tvName = findViewById(R.id.tv_detail_name)
        tvPlate = findViewById(R.id.tv_detail_plate)
        tvConnectionStatus = findViewById(R.id.tv_connection_status)
        viewStatusDot = findViewById(R.id.view_status_dot)
        loadingOverlay = findViewById(R.id.loading_overlay)
        displayInitialInfo()
    }

    private fun setupToolbar() {
        findViewById<Toolbar>(R.id.toolbar_control).setNavigationOnClickListener { finish() }
    }

    private fun setupActionListeners() {
        findViewById<View>(R.id.btn_control_unlock).setOnClickListener { controlViewModel.executeAction(currentKeyID!!, Class.FAST_ACTION, Fast.INS_UNLOCK) }
        findViewById<View>(R.id.btn_control_lock).setOnClickListener { controlViewModel.executeAction(currentKeyID!!, Class.FAST_ACTION, Fast.INS_LOCK) }
        findViewById<View>(R.id.btn_control_stop).setOnClickListener { controlViewModel.executeAction(currentKeyID!!, Class.ENGINE_OP, Fast.INS_STOP_ENGINE) }
        findViewById<View>(R.id.btn_control_trunk).setOnClickListener { controlViewModel.executeAction(currentKeyID!!, Class.FAST_ACTION, Fast.INS_OPEN_TRUNK) }

        findViewById<View>(R.id.btn_car_info).setOnClickListener { 
            BleProvider.triggerImmediateSync()
            showVehicleInfoDialog() 
        }
        findViewById<View>(R.id.btn_ekeys).setOnClickListener { 
            startActivity(Intent(this, EKeyManagerActivity::class.java).apply { putExtra("KEY_ID", currentKeyID) }) 
        }
        findViewById<View>(R.id.btn_settings).setOnClickListener { 
            startActivity(Intent(this, SettingsActivity::class.java).apply { putExtra("KEY_ID", currentKeyID) }) 
        }
    }

    private fun showActionResultDialog(success: Boolean, message: String) {
        val dialog = BottomSheetDialog(this)
        val view = LayoutInflater.from(this).inflate(R.layout.dialog_action_result, null)
        dialog.setContentView(view)
        view.findViewById<ImageView>(R.id.iv_result_icon).apply {
            setImageResource(if (success) android.R.drawable.checkbox_on_background else android.R.drawable.ic_delete)
            setColorFilter(ContextCompat.getColor(this@ControlActivity, if (success) R.color.success_green else R.color.error_red))
        }
        view.findViewById<TextView>(R.id.tv_result_title).apply {
            text = if (success) "Success" else "Action Failed"
            setTextColor(ContextCompat.getColor(this@ControlActivity, if (success) R.color.success_green else R.color.error_red))
        }
        view.findViewById<TextView>(R.id.tv_result_message).text = message
        view.findViewById<Button>(R.id.btn_result_ok).setOnClickListener { dialog.dismiss() }
        dialog.show()
    }

    private fun showNfcRecoveryDialog() {
        AlertDialog.Builder(this).setTitle("Security Sync Required").setMessage("For your protection, a secure physical synchronization is needed. Please tap your phone to the vehicle's door handle.").setPositiveButton("I UNDERSTAND", null).setCancelable(false).show()
    }

    private fun showVehicleInfoDialog() {
        val initialRecord = container.storageManager.getDigitalKey(currentKeyID) ?: return
        val dialog = BottomSheetDialog(this)
        val dialogView = LayoutInflater.from(this).inflate(R.layout.dialog_vehicle_info, null)
        dialog.setContentView(dialogView)
        dialogView.findViewById<TextView>(R.id.tv_dialog_vehicle_name).text = initialRecord.friendlyName.ifEmpty { initialRecord.carMetadata?.modelName ?: "Vehicle" }
        dialogView.findViewById<TextView>(R.id.tv_dialog_vehicle_plate).text = initialRecord.carMetadata?.licensePlate ?: "N/A"

        val telemetryListener: (VehicleStatus) -> Unit = { status -> runOnUiThread { refreshDialogUi(dialogView, status) } }
        initialRecord.vehicleStatus?.let { refreshDialogUi(dialogView, it) } ?: Toast.makeText(this, "Waiting for sync...", Toast.LENGTH_SHORT).show()

        BleProvider.setFastPolling(true)
        BleProvider.addTelemetryListener(telemetryListener)
        dialog.setOnDismissListener { 
            BleProvider.removeTelemetryListener(telemetryListener)
            BleProvider.setFastPolling(false) 
        }
        dialogView.findViewById<Button>(R.id.btn_close_status).setOnClickListener { dialog.dismiss() }
        dialog.show()
    }

    private fun refreshDialogUi(view: View, status: VehicleStatus) {
        val isRunning = status.engineState == EngineState.RUNNING
        view.findViewById<TextView>(R.id.tv_status_engine).apply {
            text = if (isRunning) "Running" else "Stopped"
            setTextColor(ContextCompat.getColor(this@ControlActivity, if (isRunning) R.color.success_green else R.color.white))
        }
        view.findViewById<ImageView>(R.id.iv_engine_icon).setColorFilter(ContextCompat.getColor(this, if (isRunning) R.color.success_green else R.color.gray_text))
        view.findViewById<TextView>(R.id.tv_status_temp).text = getString(R.string.temp_format, status.temperature)
        view.findViewById<TextView>(R.id.tv_status_battery).text = getString(R.string.battery_format, status.batteryLevel)
        view.findViewById<TextView>(R.id.tv_status_odometer).text = getString(R.string.odo_format, status.odometer)
        
        val isTrunkOpen = status.trunkState == TrunkState.OPEN
        view.findViewById<TextView>(R.id.tv_status_trunk).apply {
            text = if (isTrunkOpen) "Open" else "Closed"
            setTextColor(ContextCompat.getColor(this@ControlActivity, if (isTrunkOpen) R.color.primary_blue else R.color.white))
        }
        view.findViewById<ImageView>(R.id.iv_trunk_icon).setColorFilter(ContextCompat.getColor(this, if (isTrunkOpen) R.color.primary_blue else R.color.gray_text))

        updateDoorStatusUi(view, R.id.tv_status_door_fl, R.id.iv_door_fl_icon, status.doorStates[DoorLocation.FRONT_LEFT])
        updateDoorStatusUi(view, R.id.tv_status_door_fr, R.id.iv_door_fr_icon, status.doorStates[DoorLocation.FRONT_RIGHT])
        updateDoorStatusUi(view, R.id.tv_status_door_rl, R.id.iv_door_rl_icon, status.doorStates[DoorLocation.REAR_LEFT])
        updateDoorStatusUi(view, R.id.tv_status_door_rr, R.id.iv_door_rr_icon, status.doorStates[DoorLocation.REAR_RIGHT])
    }

    private fun updateDoorStatusUi(parent: View, tvId: Int, ivId: Int, state: DoorState?) {
        val isLocked = state == DoorState.LOCKED
        parent.findViewById<TextView>(tvId).apply {
            text = if (isLocked) "Locked" else "Unlocked"
            setTextColor(ContextCompat.getColor(this@ControlActivity, if (isLocked) R.color.white else R.color.error_red))
        }
        parent.findViewById<ImageView>(ivId).apply {
            setImageResource(if (isLocked) android.R.drawable.ic_lock_lock else android.R.drawable.ic_lock_idle_lock)
            setColorFilter(ContextCompat.getColor(this@ControlActivity, if (isLocked) R.color.gray_text else R.color.error_red))
        }
    }

    private fun refreshControlUi(status: VehicleStatus) {
        // Option to update UI elements in the main layout if they exist (e.g. mini status bar)
    }

    private fun updateBleUi(status: String) {
        val isConnected = BleProvider.getManager()?.isConnected() == true
        viewStatusDot.setBackgroundResource(if (isConnected) R.drawable.shape_dot_green else if (status.contains("Searching")) R.drawable.shape_dot_orange else R.drawable.shape_dot_grey)
        tvConnectionStatus.text = if (isConnected) "Connected" else if (status.contains("Searching")) "Searching..." else "Disconnected"
    }

    override fun onResume() { super.onResume(); BleProvider.addStatusListener(bleStatusListener) }
    override fun onPause() { super.onPause(); BleProvider.removeStatusListener(bleStatusListener) }

    private fun showInvitationResultDialog(code: String) {
        val dialog = BottomSheetDialog(this)
        val view = LayoutInflater.from(this).inflate(R.layout.dialog_invitation_result, null)
        dialog.setContentView(view)
        view.findViewById<TextView>(R.id.tv_invitation_code_display).text = code.chunked(3).joinToString(" ")
        view.findViewById<Button>(R.id.btn_done_sharing).setOnClickListener { dialog.dismiss() }
        dialog.show()
    }

    private fun displayInitialInfo() {
        container.storageManager.getDigitalKey(currentKeyID)?.let {
            tvName.text = it.friendlyName.ifEmpty { it.carMetadata?.modelName ?: "Digital Key" }
            tvPlate.text = it.carMetadata?.licensePlate ?: "NO PLATE"
            updateBleUi("Initial check")
        }
    }
}
