package com.example.a100_basiccrypto.ui.home

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
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
import com.example.a100_basiccrypto.MainApplication
import com.example.a100_basiccrypto.NotificationStore
import com.example.a100_basiccrypto.R
import com.example.a100_basiccrypto.data.model.ShareInvitation
import com.example.a100_basiccrypto.digitalkey.ble.BleForegroundService
import com.example.a100_basiccrypto.digitalkey.ble.BleHomeHelper
import com.example.a100_basiccrypto.digitalkey.ble.BleProvider
import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import com.example.a100_basiccrypto.digitalkey.nfc.MyHostApduService
import com.example.a100_basiccrypto.digitalkey.transactions.FriendPairingClient
import com.example.a100_basiccrypto.shared.crypto.DilithiumIdentityCryptoImpl
import com.example.a100_basiccrypto.shared.model.DigitalKeyPermissions
import com.example.a100_basiccrypto.shared.model.KeyState
import com.example.a100_basiccrypto.shared.model.Role
import com.example.a100_basiccrypto.ui.keycontrol.ControlActivity
import com.example.a100_basiccrypto.ui.keycontrol.PairingActivity
import com.example.a100_basiccrypto.ui.keycontrol.SharingViewModel
import com.example.a100_basiccrypto.ui.login.LoginActivity
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

    private val container by lazy { (application as MainApplication).container }
    private lateinit var homeViewModel: HomeViewModel
    private lateinit var sharingViewModel: SharingViewModel

    private lateinit var bleHomeHelper: BleHomeHelper
    private val dynamicVehicleData = mutableMapOf<String, Pair<String, Int>>()
    private val suggestedPairingDevices = mutableSetOf<String>()

    private val vehicleInfoListener: (String, String, Int) -> Unit = { mid, mac, psm ->
        runOnUiThread {
            dynamicVehicleData[mid] = Pair(mac, psm)
            keyAdapter.notifyDataSetChanged()
            checkForPendingFriendPairing(mid)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!container.authManager.isLoggedIn()) {
            startActivity(Intent(this, LoginActivity::class.java))
            finish()
            return
        }

        initViewModels()
        homeViewModel.setOnline()

        setContentView(R.layout.activity_home)

        bleHomeHelper = BleHomeHelper(this) { isEnabled ->
            if (!isEnabled) tvBleStatus.text = "Status: Bluetooth OFF"
        }

        bleHomeHelper.initLauncher {
            BleProvider.init(this)
            startBleBackgroundService(forceRefresh = true)
        }

        setupUI()
        setupObservers()

        bleHomeHelper.checkBluetoothAndRequest()
        BleProvider.init(this)
        startBleBackgroundService(forceRefresh = true)
        bleHomeHelper.registerReceiver()
    }

    private fun initViewModels() {
        homeViewModel = ViewModelProvider(this, object : ViewModelProvider.Factory {
            override fun <T : ViewModel> create(modelClass: Class<T>): T {
                @Suppress("UNCHECKED_CAST")
                return HomeViewModel(container.storageManager, container.authRepository) as T
            }
        })[HomeViewModel::class.java]

        sharingViewModel = ViewModelProvider(this, object : ViewModelProvider.Factory {
            override fun <T : ViewModel> create(modelClass: Class<T>): T {
                @Suppress("UNCHECKED_CAST")
                return SharingViewModel(
                    container.identityCrypto, 
                    container.storageManager, 
                    container.authManager,
                    container.authRepository,
                    container.keyRepository
                ) as T
            }
        })[SharingViewModel::class.java]
    }

    private fun setupObservers() {
        val email = container.authManager.getUserEmail() ?: return

        lifecycleScope.launch {
            homeViewModel.bleStatus.collectLatest { tvBleStatus.text = it }
        }

        lifecycleScope.launch {
            homeViewModel.keys.collectLatest { keyAdapter.submitList(it) }
        }

        lifecycleScope.launch {
            homeViewModel.unreadBadgeVisible.collectLatest { 
                vNotificationBadge.visibility = if (it) View.VISIBLE else View.GONE
            }
        }

        lifecycleScope.launch {
            sharingViewModel.incomingInvitations.collect { invitation ->
                NotificationStore.addNotification(email, "New Key Shared", "${invitation.senderName} shared a key with you.", invitation)
                showReceiveInvitationDialog(invitation)
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
            sharingViewModel.uiState.collectLatest { state ->
                when (state) {
                    is SharingViewModel.SharingUiState.ActivationSuccess -> {
                        Toast.makeText(this@HomeActivity, "Key added successfully!", Toast.LENGTH_LONG).show()
                        homeViewModel.refreshKeys(email)
                        startBleBackgroundService(forceRefresh = true)
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

    private fun setupUI() {
        rvKeys = findViewById(R.id.rv_keys)
        rvKeys.layoutManager = LinearLayoutManager(this)
        rvKeys.adapter = keyAdapter

        tvBleStatus = findViewById(R.id.tv_home_ble_status)
        tvHomeAppMac = findViewById(R.id.tv_home_app_mac)
        vNotificationBadge = findViewById(R.id.v_notification_badge)

        val appMac = com.example.a100_basiccrypto.digitalkey.storage.BleIdentityManager(this)
            .getAppBleAddress().joinToString(":") { "%02X".format(it) }
        tvHomeAppMac.text = "App MAC: $appMac"

        findViewById<View>(R.id.btn_add_key_header).setOnClickListener {
            startActivity(Intent(this, PairingActivity::class.java))
        }

        findViewById<View>(R.id.btn_reset_keys).setOnClickListener {
            container.storageManager.clearAll()
            container.authManager.getUserEmail()?.let { homeViewModel.refreshKeys(it) }
        }

        findViewById<View>(R.id.btn_notifications).setOnClickListener {
            startActivity(Intent(this, NotificationActivity::class.java))
        }
        
        findViewById<View>(R.id.btn_logout).setOnClickListener {
            homeViewModel.logout()
            stopService(Intent(this, BleForegroundService::class.java))
            MyHostApduService.isPairingModeEnabled = false
            MyHostApduService.friendPairingHandler = null
            startActivity(Intent(this, LoginActivity::class.java))
            finish()
        }
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

    private fun startBleBackgroundService(forceRefresh: Boolean = false) {
        if (bleHomeHelper.isBluetoothEnabled()) {
            val serviceIntent = Intent(this, BleForegroundService::class.java)
            if (forceRefresh) serviceIntent.action = BleForegroundService.ACTION_REFRESH_SCAN
            ContextCompat.startForegroundService(this, serviceIntent)
        }
    }

    override fun onResume() {
        super.onResume()
        BleProvider.addVehicleInfoListener(vehicleInfoListener)
        container.authManager.getUserEmail()?.let { homeViewModel.refreshKeys(it) }
    }

    override fun onPause() {
        super.onPause()
        BleProvider.removeVehicleInfoListener(vehicleInfoListener)
    }

    private fun checkForPendingFriendPairing(midHex: String) {
        if (suggestedPairingDevices.contains(midHex)) return
        val email = container.authManager.getUserEmail() ?: return
        val keys = container.storageManager.getKeysByAccount(email)
        val pendingKey = keys.find { key ->
            val keyMid = key.moduleID?.joinToString("") { "%02x".format(it) }
            keyMid == midHex && key.core.keyState == KeyState.PROVISIONING && key.core.role == Role.FRIEND
        }
        if (pendingKey != null) {
            suggestedPairingDevices.add(midHex)
            showFriendPairingSuggestion(pendingKey)
        }
    }

    private fun showFriendPairingSuggestion(record: DigitalKeyRecord) {
        AlertDialog.Builder(this)
            .setTitle("Vehicle Detected")
            .setMessage("Your shared key for ${record.friendlyName.ifEmpty { "this vehicle" }} is ready to be activated via Bluetooth. Would you like to start the pairing process now?")
            .setPositiveButton("Start Pairing") { _, _ -> startFriendPairingFlow(record) }
            .setNegativeButton("Not Now", null)
            .show()
    }

    private fun startFriendPairingFlow(record: DigitalKeyRecord) {
        val pairingCode = record.invitationCode ?: ""
        val transport = BleProvider.getTransport()
        if (transport == null || BleProvider.getManager()?.isConnected() != true) {
            Toast.makeText(this, "Vehicle not connected via BLE. Please wait...", Toast.LENGTH_SHORT).show()
            return
        }

        val progressDialog = AlertDialog.Builder(this)
            .setTitle("Activating Key")
            .setMessage("Establishing secure connection with vehicle...\nPlease stay near the car.")
            .setCancelable(false).create()
        progressDialog.show()

        lifecycleScope.launch {
            val client = FriendPairingClient(DilithiumIdentityCryptoImpl(), container.storageManager) { 
                Log.d("FriendPairing", it)
                runOnUiThread { progressDialog.setMessage(it) }
            }
            val success = client.execute(transport, record, pairingCode)
            progressDialog.dismiss()
            if (success) {
                AlertDialog.Builder(this@HomeActivity).setTitle("Success")
                    .setMessage("Your digital key for ${record.friendlyName} is now active and ready to use!")
                    .setPositiveButton("OK", null).show()
                container.authManager.getUserEmail()?.let { homeViewModel.refreshKeys(it) }
                startBleBackgroundService(forceRefresh = true)
            } else {
                Toast.makeText(this@HomeActivity, "Pairing failed. Please ensure you are close to the vehicle and try again.", Toast.LENGTH_LONG).show()
                suggestedPairingDevices.remove(record.moduleID?.joinToString("") { "%02x".format(it) } ?: "")
            }
        }
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
        fun submitList(newItems: List<DigitalKeyRecord>) { items = newItems; notifyDataSetChanged() }
        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
            val view = LayoutInflater.from(parent.context).inflate(R.layout.item_digital_key, parent, false)
            return ViewHolder(view)
        }
        override fun onBindViewHolder(holder: ViewHolder, position: Int) {
            val item = items[position]
            holder.tvName.text = item.keyHolderName.ifEmpty { "My Key" }
            holder.tvRoleBadge.text = if (item.core.role == Role.OWNER) "OWNER" else "FRIEND"
            holder.tvRoleBadge.setTextColor(android.graphics.Color.parseColor(if (item.core.role == Role.OWNER) "#4285F4" else "#FF9800"))
            val statusLabel = if (item.core.keyState == KeyState.PROVISIONING) " [PROVISIONING]" else ""
            holder.tvPlate.text = "${item.friendlyName.ifEmpty { "Vehicle" }} | ${item.carMetadata?.licensePlate ?: "N/A"}$statusLabel"
            holder.tvPlate.setTextColor(ContextCompat.getColor(this@HomeActivity, if (item.core.keyState == KeyState.PROVISIONING) android.R.color.holo_orange_dark else android.R.color.darker_gray))
            holder.ivCarIcon.alpha = if (item.core.keyState == KeyState.PROVISIONING) 0.5f else 1.0f
            val midHex = item.moduleID?.joinToString("") { "%02x".format(it) } ?: ""
            val dynamicData = dynamicVehicleData[midHex]
            if (homeViewModel.isL2capConnected.value && dynamicData != null) {
                holder.tvMac.visibility = View.VISIBLE; holder.tvPsm.visibility = View.VISIBLE
                holder.tvMac.text = "MAC: ${dynamicData.first}"
                holder.tvPsm.text = "PSM: 0x${Integer.toHexString(dynamicData.second).uppercase()}"
                holder.ivCarIcon.setColorFilter(ContextCompat.getColor(this@HomeActivity, android.R.color.holo_green_light))
            } else {
                holder.tvMac.visibility = View.GONE; holder.tvPsm.visibility = View.GONE
                holder.ivCarIcon.setColorFilter(ContextCompat.getColor(this@HomeActivity, android.R.color.darker_gray))
            }
            holder.itemView.setOnClickListener { onClick(item) }
        }
        override fun getItemCount() = items.size
        inner class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
            val tvName: TextView = view.findViewById(R.id.tv_item_name)
            val tvRoleBadge: TextView = view.findViewById(R.id.tv_item_role_badge)
            val tvPlate: TextView = view.findViewById(R.id.tv_item_plate)
            val tvMac: TextView = view.findViewById(R.id.tv_item_mac)
            val tvPsm: TextView = view.findViewById(R.id.tv_item_psm)
            val ivCarIcon: ImageView = view.findViewById(R.id.iv_car_icon)
        }
    }
}
