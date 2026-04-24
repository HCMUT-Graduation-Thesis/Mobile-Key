package com.example.a100_basiccrypto

import android.content.Intent
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.example.a100_basiccrypto.digitalkey.core.*
import com.example.a100_basiccrypto.digitalkey.storage.SecureKeyStorageManager
import com.example.a100_basiccrypto.digitalkey.storage.BleIdentityManager
import com.example.a100_basiccrypto.digitalkey.ble.BleProvider
import com.example.a100_basiccrypto.digitalkey.ble.BleForegroundService
import com.example.a100_basiccrypto.digitalkey.ble.BleHomeHelper
import com.example.a100_basiccrypto.shared.model.KeyState
import com.example.a100_basiccrypto.shared.command.DigitalKeyPermissions
import com.google.android.material.button.MaterialButton
import com.google.android.material.textfield.TextInputEditText
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.*

class HomeActivity : AppCompatActivity() {

    private lateinit var rvKeys: RecyclerView
    private lateinit var tvBleStatus: TextView
    private lateinit var tvHomeAppMac: TextView
    private lateinit var vNotificationBadge: View

    private val storageManager by lazy { SecureKeyStorageManager(this) }
    private val bleIdentityManager by lazy { BleIdentityManager(this) }
    private val authManager by lazy { AuthManager(this) }
    private lateinit var sharingViewModel: SharingViewModel

    private lateinit var bleHomeHelper: BleHomeHelper

    private val dynamicVehicleData = mutableMapOf<String, Pair<String, Int>>()
    private var isL2capConnected = false

    private val bleStatusListener: (String) -> Unit = { message ->
        runOnUiThread { tvBleStatus.text = "Status: $message" }
    }

    private val vehicleInfoListener: (String, String, Int) -> Unit = { mid, mac, psm ->
        runOnUiThread {
            dynamicVehicleData[mid] = Pair(mac, psm)
            keyAdapter.notifyDataSetChanged()
        }
    }

    private val connectionStateListener: (Boolean) -> Unit = { isConnected ->
        runOnUiThread {
            isL2capConnected = isConnected
            if (!isConnected) dynamicVehicleData.clear()
            keyAdapter.notifyDataSetChanged()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!authManager.isLoggedIn()) {
            startActivity(Intent(this, LoginActivity::class.java))
            finish()
            return
        }

        val email = authManager.getUserEmail()
        if (email != null) MockKeyServer.setOnline(email)

        setContentView(R.layout.activity_home)

        bleHomeHelper = BleHomeHelper(this) { isEnabled ->
            if (::tvBleStatus.isInitialized) updateBleStatus(isEnabled)
        }

        bleHomeHelper.initLauncher {
            updateBleStatus(true)
            BleProvider.init(this)
            startBleBackgroundService()
        }

        setupUI()
        initViewModel()
        setupSharingObservers()

        bleHomeHelper.checkBluetoothAndRequest()
        BleProvider.init(this)
        startBleBackgroundService()
        bleHomeHelper.registerReceiver()
    }

    private fun setupSharingObservers() {
        val email = authManager.getUserEmail() ?: return

        lifecycleScope.launch {
            sharingViewModel.incomingInvitations.collect { invitation ->
                NotificationStore.addNotification(email, "New Key Shared", "${invitation.senderName} shared a key with you.", invitation)
                showReceiveInvitationDialog(invitation)
            }
        }

        lifecycleScope.launch {
            NotificationStore.unreadBadgeVisible.collect { isVisible ->
                vNotificationBadge.visibility = if (isVisible) View.VISIBLE else View.GONE
            }
        }

        lifecycleScope.launch {
            NotificationStore.pendingInvitation.collect { invitation ->
                invitation?.let {
                    showReceiveInvitationDialog(it)
                    NotificationStore.setPendingInvitation(null)
                }
            }
        }

        lifecycleScope.launch {
            sharingViewModel.uiState.collect { state ->
                when (state) {
                    is SharingViewModel.SharingUiState.ActivationSuccess -> {
                        Toast.makeText(this@HomeActivity, "Key added successfully!", Toast.LENGTH_LONG).show()
                        refreshList()
                    }
                    is SharingViewModel.SharingUiState.Error -> {
                        Toast.makeText(this@HomeActivity, state.message, Toast.LENGTH_SHORT).show()
                    }
                    else -> {}
                }
            }
        }

        sharingViewModel.fetchInvitationsFromCloud(email)
    }

    private fun showReceiveInvitationDialog(invitation: ShareInvitation) {
        val dialogView = LayoutInflater.from(this).inflate(R.layout.dialog_receive_invitation, null)
        val dialog = AlertDialog.Builder(this).setView(dialogView).create()

        val tvOwner = dialogView.findViewById<TextView>(R.id.tv_invitation_detail_owner)
        val tvPerms = dialogView.findViewById<TextView>(R.id.tv_invitation_detail_perms)
        val tvValidity = dialogView.findViewById<TextView>(R.id.tv_invitation_detail_validity)
        val etCode = dialogView.findViewById<TextInputEditText>(R.id.et_invitation_code)
        val btnProvision = dialogView.findViewById<MaterialButton>(R.id.btn_accept_invitation)

        val record = sharingViewModel.onInvitationReceived(invitation)
        tvOwner.text = "Sender: ${invitation.senderName}"
        
        val permissions = record?.core?.permissions ?: 0
        val permsList = mutableListOf<String>()
        if (permissions and DigitalKeyPermissions.UNLOCK != 0) permsList.add("Unlock")
        if (permissions and DigitalKeyPermissions.LOCK != 0) permsList.add("Lock")
        if (permissions and DigitalKeyPermissions.START != 0) permsList.add("Start")
        tvPerms.text = "Permissions: ${if(permsList.isEmpty()) "Basic" else permsList.joinToString(", ")}"
        
        val validityEnd = record?.core?.validityEnd ?: 0L
        val sdf = SimpleDateFormat("yyyy-MM-dd", Locale.getDefault())
        tvValidity.text = "Expires: ${if (validityEnd > 0L) sdf.format(Date(validityEnd * 1000)) else "Never"}"

        btnProvision.setOnClickListener {
            val pin = etCode.text.toString()
            if (pin.length == 6 && record != null) {
                sharingViewModel.verifyPinAndActivate(record, pin, invitation)
                dialog.dismiss()
            } else {
                Toast.makeText(this, "Please enter 6-digit code", Toast.LENGTH_SHORT).show()
            }
        }
        dialog.show()
    }

    private fun updateBleStatus(isEnabled: Boolean) {
        tvBleStatus.text = if (!isEnabled) "Status: Bluetooth OFF" else "Status: Initializing..."
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
        vNotificationBadge = findViewById(R.id.v_notification_badge)

        val appMac = bleIdentityManager.getAppBleAddress().joinToString(":") { "%02X".format(it) }
        tvHomeAppMac.text = "App MAC: $appMac"

        findViewById<View>(R.id.btn_add_key_header).setOnClickListener {
            startActivity(Intent(this, PairingActivity::class.java))
        }

        findViewById<View>(R.id.btn_reset_keys).setOnClickListener {
            storageManager.clearAll()
            refreshList()
        }

        findViewById<View>(R.id.btn_notifications).setOnClickListener {
            startActivity(Intent(this, NotificationActivity::class.java))
        }
        
        findViewById<View>(R.id.btn_logout).setOnClickListener {
            authManager.getUserEmail()?.let { MockKeyServer.setOffline(it) }
            authManager.logout()
            stopService(Intent(this, BleForegroundService::class.java))
            startActivity(Intent(this, LoginActivity::class.java))
            finish()
        }
    }

    private fun initViewModel() {
        sharingViewModel = ViewModelProvider(this, object : ViewModelProvider.Factory {
            override fun <T : ViewModel> create(modelClass: Class<T>): T {
                @Suppress("UNCHECKED_CAST")
                return SharingViewModel(com.example.a100_basiccrypto.shared.crypto.DilithiumIdentityCryptoImpl(), storageManager, authManager) as T
            }
        })[SharingViewModel::class.java]
    }

    override fun onResume() {
        super.onResume()
        if (!authManager.isLoggedIn()) return
        BleProvider.addStatusListener(bleStatusListener)
        BleProvider.addVehicleInfoListener(vehicleInfoListener)
        BleProvider.addConnectionStateListener(connectionStateListener)
        refreshList()
        if (bleHomeHelper.isBluetoothEnabled()) startBleBackgroundService()
    }

    override fun onPause() {
        super.onPause()
        BleProvider.removeStatusListener(bleStatusListener)
        BleProvider.removeVehicleInfoListener(vehicleInfoListener)
        BleProvider.removeConnectionStateListener(connectionStateListener)
    }

    private fun refreshList() {
        val email = authManager.getUserEmail() ?: return
        val visibleKeys = storageManager.getAllKeys().filter {
            it.accountEmail == email && 
            (it.core.keyState == KeyState.ACTIVE || it.core.keyState == KeyState.PROVISIONING) 
        }
        keyAdapter.submitList(visibleKeys)
    }

    private val keyAdapter = KeyAdapter { record ->
        if (record.core.keyState == KeyState.ACTIVE || record.core.keyState == KeyState.PROVISIONING) {
            val intent = Intent(this, ControlActivity::class.java)
            intent.putExtra("KEY_ID", record.core.keyID)
            startActivity(intent)
        } else {
            Toast.makeText(this, "Key not ready.", Toast.LENGTH_SHORT).show()
        }
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
            // UPDATED UI: Holder Name as Title, Car Name as Subtitle
            holder.tvName.text = item.keyHolderName.ifEmpty { "My Digital Key" }

            val statusLabel = if (item.core.keyState == KeyState.PROVISIONING) " [PROVISIONING]" else ""
            holder.tvPlate.text = "${item.friendlyName}$statusLabel"
            
            if (item.core.keyState == KeyState.PROVISIONING) {
                holder.tvPlate.setTextColor(ContextCompat.getColor(this@HomeActivity, android.R.color.holo_orange_dark))
                holder.ivCarIcon.alpha = 0.5f
            } else {
                holder.tvPlate.setTextColor(ContextCompat.getColor(this@HomeActivity, android.R.color.darker_gray))
                holder.ivCarIcon.alpha = 1.0f
            }

            val midHex = item.moduleID?.joinToString("") { "%02x".format(it) } ?: ""
            val dynamicData = dynamicVehicleData[midHex]
            if (isL2capConnected && dynamicData != null) {
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
            val ivCarIcon: ImageView = view.findViewById(R.id.iv_car_icon)
        }
    }
}
