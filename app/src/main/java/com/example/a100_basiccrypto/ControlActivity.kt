package com.example.a100_basiccrypto

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.widget.Button
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.core.content.ContextCompat
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
import com.example.a100_basiccrypto.shared.model.DoorLocation
import com.example.a100_basiccrypto.shared.model.DoorState
import com.example.a100_basiccrypto.shared.model.EngineState
import com.example.a100_basiccrypto.shared.model.TrunkState
import com.example.a100_basiccrypto.shared.model.VehicleStatus
import com.google.android.material.bottomsheet.BottomSheetDialog
import kotlinx.coroutines.launch

/**
 * ControlActivity - Manages BLE Active control flow.
 * Ensures counter sync by passing only KeyID to the Transaction Client.
 */
class ControlActivity : AppCompatActivity() {

    private lateinit var tvName: TextView
    private lateinit var tvPlate: TextView
    private lateinit var tvConnectionStatus: TextView
    private lateinit var viewStatusDot: View
    private lateinit var loadingOverlay: View
    
    private val storageManager by lazy { SecureKeyStorageManager(this) }
    private var currentKeyID: ByteArray? = null

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
            Log.d("ControlActivity", "FastTx: $message")
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
        findViewById<View>(R.id.btn_control_stop).setOnClickListener {
            performFastAction(Class.ENGINE_OP, Fast.INS_STOP_ENGINE)
        }
        findViewById<View>(R.id.btn_control_trunk).setOnClickListener { 
            performFastAction(Class.FAST_ACTION, Fast.INS_OPEN_TRUNK) 
        }

        findViewById<View>(R.id.btn_car_info).setOnClickListener {
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

    private fun performFastAction(msgClass: Byte, targetIns: Byte) {
        val keyID = currentKeyID ?: return
        
        if (!BleProvider.getManager().isConnected()) {
            Toast.makeText(this, "BLE not connected. Use NFC or wait.", Toast.LENGTH_SHORT).show()
            return
        }

        lifecycleScope.launch {
            loadingOverlay.visibility = View.VISIBLE
            
            val success = fastTxClient.execute(
                transport = BleProvider.getTransport(),
                keyID = keyID,
                msgClass = msgClass,
                targetIns = targetIns
            )

            loadingOverlay.visibility = View.GONE
            
            if (success) {
                Toast.makeText(this@ControlActivity, "Action Successful!", Toast.LENGTH_SHORT).show()
            } else {
                Toast.makeText(this@ControlActivity, "Action Failed. Check log.", Toast.LENGTH_SHORT).show()
            }
        }
    }

    /**
     * Shows the BottomSheetDialog with vehicle telemetry information.
     * Supports real-time updates via BleProvider telemetry listener.
     */
    private fun showVehicleInfoDialog() {
        val keyID = currentKeyID ?: return
        val initialRecord = storageManager.getDigitalKey(keyID) ?: return
        
        val dialog = BottomSheetDialog(this)
        val dialogView = LayoutInflater.from(this).inflate(R.layout.dialog_vehicle_info, null)
        dialog.setContentView(dialogView)

        // Set static Header Info once
        dialogView.findViewById<TextView>(R.id.tv_dialog_vehicle_name).text = 
            initialRecord.friendlyName.ifEmpty { initialRecord.carMetadata?.modelName ?: "Vehicle" }
        dialogView.findViewById<TextView>(R.id.tv_dialog_vehicle_plate).text = 
            initialRecord.carMetadata?.licensePlate ?: "N/A"

        // Telemetry listener for real-time updates
        val telemetryListener: (VehicleStatus) -> Unit = { status ->
            runOnUiThread {
                refreshDialogUi(dialogView, status)
            }
        }

        // Initial UI population
        initialRecord.vehicleStatus?.let { refreshDialogUi(dialogView, it) } ?: run {
            Toast.makeText(this, "Waiting for telemetry sync...", Toast.LENGTH_SHORT).show()
        }

        // Start listening for updates while dialog is open
        BleProvider.addTelemetryListener(telemetryListener)

        // Stop listening when dialog is closed
        dialog.setOnDismissListener {
            BleProvider.removeTelemetryListener(telemetryListener)
        }

        dialogView.findViewById<Button>(R.id.btn_close_status).setOnClickListener { dialog.dismiss() }
        dialog.show()
    }

    private fun refreshDialogUi(view: View, status: VehicleStatus) {
        // Engine UI
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

        // Core Telemetry
        view.findViewById<TextView>(R.id.tv_status_temp).text = getString(R.string.temp_format, status.temperature)
        view.findViewById<TextView>(R.id.tv_status_battery).text = getString(R.string.battery_format, status.batteryLevel)
        view.findViewById<TextView>(R.id.tv_status_odometer).text = getString(R.string.odo_format, status.odometer)

        // Trunk UI
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

        // 4 Doors Detailed UI
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
        val isConnected = try { BleProvider.getManager().isConnected() } catch(e: Exception) { false }
        
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
