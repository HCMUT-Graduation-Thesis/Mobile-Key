package com.example.a100_basiccrypto

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.example.a100_basiccrypto.digitalkey.core.*
import com.example.a100_basiccrypto.digitalkey.nfc.MyHostApduService
import com.example.a100_basiccrypto.digitalkey.storage.SecureKeyStorageManager
import com.example.a100_basiccrypto.digitalkey.transactions.FriendPairingTransaction
import com.example.a100_basiccrypto.shared.command.MessageConstants
import com.example.a100_basiccrypto.shared.command.SharingConstants
import com.example.a100_basiccrypto.shared.crypto.CryptoUtils
import com.example.a100_basiccrypto.shared.crypto.DilithiumIdentityCryptoImpl
import com.example.a100_basiccrypto.shared.model.KeyState
import com.example.a100_basiccrypto.shared.model.Role
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.google.android.material.textfield.TextInputEditText
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.launch

class HomeActivity : AppCompatActivity() {

    private lateinit var rvKeys: RecyclerView
    private lateinit var tvNotificationBadge: TextView
    
    private val storageManager by lazy { SecureKeyStorageManager(this) }
    private lateinit var sharingViewModel: SharingViewModel

    private val nfcResultReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val actionName = intent?.getStringExtra("action_name")
            val isSuccess = intent?.getBooleanExtra("is_success", false) ?: false
            
            if (actionName == "FRIEND PAIRING" && isSuccess) {
                activePairingDialog?.let { dialog ->
                    val title = dialog.findViewById<TextView>(R.id.tv_phase_title)
                    val status = dialog.findViewById<TextView>(R.id.tv_phase_status)
                    val loading = dialog.findViewById<View>(R.id.cp_pairing_loading)
                    val successIcon = dialog.findViewById<View>(R.id.iv_pairing_success)

                    loading?.visibility = View.GONE
                    successIcon?.visibility = View.VISIBLE
                    title?.text = "Success!"
                    status?.text = "Friend key activated via NFC."
                    
                    lifecycleScope.launch {
                        kotlinx.coroutines.delay(2000)
                        dialog.dismiss()
                        activePairingDialog = null
                        MyHostApduService.friendPairingHandler = null
                        refreshList()
                    }
                }
            }
        }
    }

    private var activePairingDialog: AlertDialog? = null

    private val keyAdapter = KeyAdapter { record ->
        val intent = Intent(this, ControlActivity::class.java)
        intent.putExtra("KEY_ID", record.core.keyID)
        startActivity(intent)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_home)

        sharingViewModel = ViewModelProvider(this, object : ViewModelProvider.Factory {
            override fun <T : ViewModel> create(modelClass: Class<T>): T {
                @Suppress("UNCHECKED_CAST")
                return SharingViewModel(DilithiumIdentityCryptoImpl(), storageManager) as T
            }
        })[SharingViewModel::class.java]

        setupHeader()
        
        rvKeys = findViewById(R.id.rv_keys)
        rvKeys.layoutManager = LinearLayoutManager(this)
        rvKeys.adapter = keyAdapter

        observeViewModel()
        observePendingInvitations()
        
        // Use compatibility method for registerReceiver
        val filter = IntentFilter(MyHostApduService.ACTION_NFC_RESULT)
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(nfcResultReceiver, filter, Context.RECEIVER_EXPORTED)
        } else {
            registerReceiver(nfcResultReceiver, filter)
        }
    }

    private fun setupHeader() {
        findViewById<View>(R.id.btn_notifications).setOnClickListener {
            startActivity(Intent(this, NotificationActivity::class.java))
        }
        
        findViewById<View>(R.id.btn_reset_keys).setOnClickListener {
            showResetConfirmation()
        }

        findViewById<View>(R.id.btn_add_key_header).setOnClickListener {
            if (storageManager.getAllKeys().size >= 5) {
                Toast.makeText(this, "Maximum 5 keys allowed", Toast.LENGTH_SHORT).show()
            } else {
                startActivity(Intent(this, PairingActivity::class.java))
            }
        }
        tvNotificationBadge = findViewById(R.id.tv_notification_badge)
    }

    private fun showResetConfirmation() {
        AlertDialog.Builder(this)
            .setTitle("Reset All Keys")
            .setMessage("Are you sure you want to delete all digital keys? This cannot be undone.")
            .setPositiveButton("Reset") { _, _ ->
                storageManager.clearAll()
                refreshList()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun observeViewModel() {
        sharingViewModel.incomingInvitations
            .onEach { invitation ->
                runOnUiThread { 
                    tvNotificationBadge.visibility = View.VISIBLE
                    tvNotificationBadge.text = "1"
                    NotificationStore.addNotification("Share Key", "A new digital key has been shared with you.", invitation)
                }
            }
            .launchIn(lifecycleScope)
    }

    private fun observePendingInvitations() {
        NotificationStore.pendingInvitation
            .onEach { invitation ->
                if (invitation != null) {
                    val isUsed = NotificationStore.notifications.value.find { it.invitation == invitation }?.isUsed ?: false
                    if (!isUsed) {
                        runOnUiThread { showReceiveInvitationDialog(invitation) }
                    } else {
                        NotificationStore.setPendingInvitation(null)
                    }
                }
            }
            .launchIn(lifecycleScope)
    }

    private fun showReceiveInvitationDialog(invitation: ShareInvitation) {
        lifecycleScope.launch {
            val dialog = BottomSheetDialog(this@HomeActivity)
            val view = LayoutInflater.from(this@HomeActivity).inflate(R.layout.dialog_receive_invitation, null)
            dialog.setContentView(view)

            val tempRecord = SharingManager(DilithiumIdentityCryptoImpl(), storageManager).processIncomingInvitation(invitation)
            if (tempRecord == null) {
                Toast.makeText(this@HomeActivity, "Invalid invitation", Toast.LENGTH_SHORT).show()
                return@launch
            }
            
            view.findViewById<TextView>(R.id.tv_invitation_detail_owner).text = "From: ${invitation.senderName}"
            view.findViewById<TextView>(R.id.tv_invitation_detail_perms).text = "Permissions: ${getPermissionsString(tempRecord.core.permissions)}"

            view.findViewById<Button>(R.id.btn_accept_invitation).setOnClickListener {
                val enteredCode = view.findViewById<TextInputEditText>(R.id.et_invitation_code).text.toString()
                val ownerID = tempRecord.core.parentKeyID ?: ByteArray(8)
                val enteredHash = CryptoUtils.hmacSha256(ownerID, enteredCode.toByteArray())
                
                if (enteredHash.contentEquals(tempRecord.invitationCodeHash)) {
                    dialog.dismiss()
                    prepareNfcFriendPairing(tempRecord, invitation, enteredCode)
                } else {
                    Toast.makeText(this@HomeActivity, "Invalid Code", Toast.LENGTH_SHORT).show()
                }
            }
            dialog.setOnDismissListener { NotificationStore.setPendingInvitation(null) }
            dialog.show()
        }
    }

    private fun prepareNfcFriendPairing(record: DigitalKeyRecord, invitation: ShareInvitation, code: String) {
        // Prepare the handler for MyHostApduService
        val handler = FriendPairingTransaction(
            identityCrypto = DilithiumIdentityCryptoImpl(),
            storageManager = storageManager,
            record = record,
            pairingCode = code,
            onLog = { runOnUiThread { Log.d("PairingLog", it) } }
        )
        
        MyHostApduService.friendPairingHandler = handler
        
        // Show the UI waiting for NFC tap
        val pairingView = LayoutInflater.from(this).inflate(R.layout.dialog_nfc_pairing, null)
        activePairingDialog = AlertDialog.Builder(this)
            .setView(pairingView)
            .setCancelable(true)
            .setOnDismissListener { 
                MyHostApduService.friendPairingHandler = null 
            }
            .create()

        activePairingDialog?.show()
        
        pairingView.findViewById<TextView>(R.id.tv_phase_title).text = "Ready to Pair"
        pairingView.findViewById<TextView>(R.id.tv_phase_status).text = "Please tap your phone to the vehicle Reader to finish pairing."
    }

    private fun getPermissionsString(perms: Int): String {
        val list = mutableListOf<String>()
        if (perms and SharingConstants.PERM_UNLOCK != 0) list.add("Unlock")
        if (perms and SharingConstants.PERM_LOCK != 0) list.add("Lock")
        if (perms and SharingConstants.PERM_START != 0) list.add("Start")
        return list.joinToString(", ")
    }

    override fun onResume() {
        super.onResume()
        refreshList()
    }

    override fun onDestroy() {
        super.onDestroy()
        unregisterReceiver(nfcResultReceiver)
    }

    private fun refreshList() {
        val keys = storageManager.getAllKeys()
        val activeKeys = keys.filter { it.core.keyState == KeyState.ACTIVE }
        keyAdapter.submitList(activeKeys)
    }

    class KeyAdapter(private val onClick: (DigitalKeyRecord) -> Unit) :
        RecyclerView.Adapter<KeyAdapter.ViewHolder>() {

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
            holder.tvName.text = if (item.friendlyName.isNotEmpty()) item.friendlyName else (item.core.carMetadata?.modelName ?: "Vehicle")
            holder.tvPlate.text = item.core.carMetadata?.licensePlate ?: "No Plate"
            holder.tvRole.text = item.core.role.name
            holder.itemView.setOnClickListener { onClick(item) }
        }

        override fun getItemCount() = items.size

        class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
            val tvName: TextView = view.findViewById(R.id.tv_item_name)
            val tvPlate: TextView = view.findViewById(R.id.tv_item_plate)
            val tvRole: TextView = view.findViewById(R.id.tv_item_role_badge)
        }
    }
}
