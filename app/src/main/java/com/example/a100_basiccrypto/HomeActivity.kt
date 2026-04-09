package com.example.a100_basiccrypto

import android.content.Intent
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.example.a100_basiccrypto.digitalkey.core.*
import com.example.a100_basiccrypto.digitalkey.storage.SecureKeyStorageManager
import com.example.a100_basiccrypto.digitalkey.storage.BleIdentityManager
import com.example.a100_basiccrypto.digitalkey.ble.BleProvider
import com.example.a100_basiccrypto.digitalkey.ble.BleForegroundService
import com.example.a100_basiccrypto.digitalkey.ble.BleHomeHelper
import com.example.a100_basiccrypto.shared.model.KeyState

class HomeActivity : AppCompatActivity() {

    private lateinit var rvKeys: RecyclerView
    private lateinit var tvNotificationBadge: TextView
    private lateinit var tvBleStatus: TextView
    private lateinit var tvHomeAppMac: TextView

    private val storageManager by lazy { SecureKeyStorageManager(this) }
    private val bleIdentityManager by lazy { BleIdentityManager(this) }
    private lateinit var sharingViewModel: SharingViewModel

    private lateinit var bleHomeHelper: BleHomeHelper

    // Track dynamic vehicle data (Cleared on disconnect)
    private val dynamicVehicleData = mutableMapOf<String, Pair<String, Int>>()

    private val bleStatusListener: (String) -> Unit = { message ->
        runOnUiThread {
            tvBleStatus.text = "Status: $message"
            // If link is lost, clear the technical info from cards
            if (message.contains("Link lost") || message.contains("Searching")) {
                dynamicVehicleData.clear()
                keyAdapter.notifyDataSetChanged()
            }
        }
    }

    private val vehicleInfoListener: (String, String, Int) -> Unit = { mid, mac, psm ->
        runOnUiThread {
            dynamicVehicleData[mid] = Pair(mac, psm)
            keyAdapter.notifyDataSetChanged()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_home)

        // 1. Initialize BleHomeHelper early (but don't use it yet)
        bleHomeHelper = BleHomeHelper(this) { isEnabled ->
            if (::tvBleStatus.isInitialized) {
                updateBleStatus(isEnabled)
            }
        }

        // 2. Initialize launcher (must be called before setupUI if setupUI triggers checks)
        bleHomeHelper.initLauncher {
            updateBleStatus(true)
            BleProvider.init(this)
            startBleBackgroundService()
        }

        // 3. Initialize UI (setupUI now uses bleHomeHelper safely)
        setupUI()
        initViewModel()

        // 4. Perform Bluetooth checks
        bleHomeHelper.checkBluetoothAndRequest()
        
        // 5. Follow-up original onCreate logic
        BleProvider.init(this)
        startBleBackgroundService()

        // 6. Register state changed receiver
        bleHomeHelper.registerReceiver()
    }

    private fun updateBleStatus(isEnabled: Boolean) {
        if (!isEnabled) {
            tvBleStatus.text = "Status: Bluetooth OFF"
        } else {
            // Check if we are coming from an OFF state
            if (tvBleStatus.text.contains("OFF")) {
                tvBleStatus.text = "Status: Initializing..."
            }
        }
    }

    private fun startBleBackgroundService() {
        if (bleHomeHelper.isBluetoothEnabled()) {
            val serviceIntent = Intent(this, BleForegroundService::class.java)
            ContextCompat.startForegroundService(this, serviceIntent)
        }
    }

    private fun setupUI() {
        rvKeys = findViewById(R.id.rv_keys)
        rvKeys.layoutManager = LinearLayoutManager(this)
        rvKeys.adapter = keyAdapter

        tvBleStatus = findViewById(R.id.tv_home_ble_status)
        tvHomeAppMac = findViewById(R.id.tv_home_app_mac)

        // Initial update based on current state
        updateBleStatus(bleHomeHelper.isBluetoothEnabled())

        val appMac = bleIdentityManager.getAppBleAddress().joinToString(":") { "%02X".format(it) }
        tvHomeAppMac.text = "App MAC: $appMac"

        findViewById<View>(R.id.btn_add_key_header).setOnClickListener {
            startActivity(Intent(this, PairingActivity::class.java))
        }

        findViewById<View>(R.id.btn_reset_keys).setOnClickListener {
            storageManager.clearAll()
            refreshList()
        }
    }

    private fun initViewModel() {
        sharingViewModel = ViewModelProvider(this, object : ViewModelProvider.Factory {
            override fun <T : ViewModel> create(modelClass: Class<T>): T {
                @Suppress("UNCHECKED_CAST")
                return SharingViewModel(com.example.a100_basiccrypto.shared.crypto.DilithiumIdentityCryptoImpl(), storageManager) as T
            }
        })[SharingViewModel::class.java]
    }

    override fun onResume() {
        super.onResume()
        BleProvider.addStatusListener(bleStatusListener)
        BleProvider.addVehicleInfoListener(vehicleInfoListener)
        updateBleStatus(bleHomeHelper.isBluetoothEnabled())
        refreshList()
    }

    override fun onPause() {
        super.onPause()
        BleProvider.removeStatusListener(bleStatusListener)
        BleProvider.removeVehicleInfoListener(vehicleInfoListener)
    }

    override fun onDestroy() {
        super.onDestroy()
        bleHomeHelper.unregisterReceiver()
    }

    private fun refreshList() {
        val keys = storageManager.getAllKeys()
        val activeKeys = keys.filter { it.core.keyState == KeyState.ACTIVE }
        keyAdapter.submitList(activeKeys)
    }

    private val keyAdapter = KeyAdapter { record ->
        val intent = Intent(this, ControlActivity::class.java)
        intent.putExtra("KEY_ID", record.core.keyID)
        startActivity(intent)
    }

    inner class KeyAdapter(private val onClick: (DigitalKeyRecord) -> Unit) : RecyclerView.Adapter<KeyAdapter.ViewHolder>() {
        private var items = listOf<DigitalKeyRecord>()

        fun submitList(newItems: List<DigitalKeyRecord>) {
            items = newItems
            notifyDataSetChanged()
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
            val view = LayoutInflater.from(parent.context).inflate(R.layout.item_digital_key, parent, false)
            return ViewHolder(view)
        }

        override fun onBindViewHolder(holder: ViewHolder, position: Int) {
            val item = items[position]
            holder.tvName.text = if (item.friendlyName.isNotEmpty()) item.friendlyName else (item.carMetadata?.modelName ?: "Vehicle")
            holder.tvPlate.text = item.carMetadata?.licensePlate ?: "No Plate"

            // Format ModuleID to hex for lookup
            val midHex = item.moduleID?.joinToString("") { "%02x".format(it) } ?: ""
            val dynamicData = dynamicVehicleData[midHex]

            if (dynamicData != null) {
                holder.tvMac.visibility = View.VISIBLE
                holder.tvPsm.visibility = View.VISIBLE
                holder.tvMac.text = "MAC: ${dynamicData.first}"
                holder.tvPsm.text = "PSM: 0x${Integer.toHexString(dynamicData.second).uppercase()}"
                holder.ivCarIcon.setColorFilter(ContextCompat.getColor(this@HomeActivity, android.R.color.holo_green_light))
            } else {
                holder.tvMac.visibility = View.GONE
                holder.tvPsm.visibility = View.GONE
                holder.ivCarIcon.setColorFilter(ContextCompat.getColor(this@HomeActivity, android.R.color.darker_gray))
            }

            holder.itemView.setOnClickListener { onClick(item) }
        }

        override fun getItemCount() = items.size

        inner class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
            val tvName: TextView = view.findViewById(R.id.tv_item_name)
            val tvPlate: TextView = view.findViewById(R.id.tv_item_plate)
            val tvMac: TextView = view.findViewById(R.id.tv_item_mac)
            val tvPsm: TextView = view.findViewById(R.id.tv_item_psm)
            val ivCarIcon: android.widget.ImageView = view.findViewById(R.id.iv_car_icon)
        }
    }
}
