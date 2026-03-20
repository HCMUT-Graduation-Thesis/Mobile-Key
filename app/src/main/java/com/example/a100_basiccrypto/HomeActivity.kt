package com.example.a100_basiccrypto

import android.content.Intent
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
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.example.a100_basiccrypto.digitalkey.core.*
import com.example.a100_basiccrypto.digitalkey.crypto.CryptoUtils
import com.example.a100_basiccrypto.digitalkey.crypto.CryptoUtils.toHex
import com.example.a100_basiccrypto.digitalkey.crypto.DilithiumIdentityCryptoImpl
import com.example.a100_basiccrypto.digitalkey.storage.SecureKeyStorageManager
import com.example.a100_basiccrypto.shared.model.KeyState
import com.example.a100_basiccrypto.shared.model.Role
import com.example.a100_basiccrypto.shared.command.SharingConstants
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.google.android.material.textfield.TextInputEditText
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach

class HomeActivity : AppCompatActivity() {

    private lateinit var rvKeys: RecyclerView
    private lateinit var tvNotificationBadge: TextView
    
    private val storageManager by lazy { SecureKeyStorageManager(this) }
    private lateinit var sharingViewModel: SharingViewModel

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
                return SharingViewModel(DilithiumIdentityCryptoImpl(), storageManager) as T
            }
        })[SharingViewModel::class.java]

        setupHeader()
        
        rvKeys = findViewById(R.id.rv_keys)
        rvKeys.layoutManager = LinearLayoutManager(this)
        rvKeys.adapter = keyAdapter

        observeViewModel()
        observePendingInvitations()
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
            .setMessage("Are you sure you want to delete all digital keys from this device? This action cannot be undone.")
            .setPositiveButton("Reset") { _, _ ->
                storageManager.clearAll()
                refreshList()
                Toast.makeText(this, "Storage Cleared", Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton("Cancel", null)
            .create()
            .apply {
                show()
                getButton(AlertDialog.BUTTON_POSITIVE).setTextColor(getColor(R.color.error_red))
            }
    }

    private fun observeViewModel() {
        sharingViewModel.incomingInvitations
            .onEach { ap ->
                runOnUiThread { 
                    tvNotificationBadge.visibility = View.VISIBLE
                    tvNotificationBadge.text = "1"
                    NotificationStore.addNotification("Share Key", "A new digital key has been shared with you.", ap)
                }
            }
            .launchIn(lifecycleScope)

        lifecycleScope.launchWhenStarted {
            sharingViewModel.uiState.collect { state ->
                when (state) {
                    is SharingViewModel.SharingUiState.ReceivedInvitation -> {
                        refreshList()
                        tvNotificationBadge.visibility = View.GONE
                        NotificationStore.setPendingInvitation(null)
                        sharingViewModel.resetState()
                    }
                    is SharingViewModel.SharingUiState.Error -> {
                        Toast.makeText(this@HomeActivity, state.message, Toast.LENGTH_LONG).show()
                    }
                    else -> {}
                }
            }
        }
    }

    private fun observePendingInvitations() {
        NotificationStore.pendingInvitation
            .onEach { ap ->
                if (ap != null) {
                    runOnUiThread {
                        showReceiveInvitationDialog(ap)
                    }
                }
            }
            .launchIn(lifecycleScope)
    }

    private fun showReceiveInvitationDialog(ap: ByteArray) {
        lifecycleScope.launchWhenStarted {
            val dialog = BottomSheetDialog(this@HomeActivity)
            val view = LayoutInflater.from(this@HomeActivity).inflate(R.layout.dialog_receive_invitation, null)
            dialog.setContentView(view)

            val tempRecord = SharingManager(DilithiumIdentityCryptoImpl(), storageManager).processIncomingInvitation(ap)
            if (tempRecord == null) {
                Toast.makeText(this@HomeActivity, "Invalid invitation data", Toast.LENGTH_SHORT).show()
                return@launchWhenStarted
            }
            
            view.findViewById<TextView>(R.id.tv_invitation_detail_owner).text = "Owner ID: ${tempRecord.core.parentKeyID?.toHex()?.take(8) ?: "Unknown"}"
            view.findViewById<TextView>(R.id.tv_invitation_detail_perms).text = "Permissions: ${getPermissionsString(tempRecord.core.permissions)}"
            view.findViewById<TextView>(R.id.tv_invitation_detail_validity).text = "Expires: ${if (tempRecord.core.validityEnd == 0L) "Never" else java.util.Date(tempRecord.core.validityEnd * 1000).toString()}"

            view.findViewById<Button>(R.id.btn_accept_invitation).setOnClickListener {
                val enteredCode = view.findViewById<TextInputEditText>(R.id.et_invitation_code).text.toString()
                val enteredHash = CryptoUtils.sha256(enteredCode.toByteArray())
                if (enteredHash.contentEquals(tempRecord.invitationCodeHash)) {
                    SharingManager(DilithiumIdentityCryptoImpl(), storageManager).finalizeProvisioning(tempRecord)
                    sharingViewModel.processInvitation(ap)
                    dialog.dismiss()
                } else {
                    Toast.makeText(this@HomeActivity, "Invalid Invitation Code", Toast.LENGTH_SHORT).show()
                }
            }
            dialog.setOnDismissListener {
                NotificationStore.setPendingInvitation(null)
            }
            dialog.show()
        }
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

    private fun refreshList() {
        val keys = storageManager.getAllKeys()
        val activeKeys = keys.filter { it.core.keyState != KeyState.PENDING }
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
            val context = holder.itemView.context
            
            holder.tvName.text = if (item.friendlyName.isNotEmpty()) item.friendlyName else (item.core.carMetadata?.modelName ?: "Unknown Vehicle")
            holder.tvPlate.text = item.core.carMetadata?.licensePlate ?: "No Plate Info"
            holder.tvRole.text = item.core.role.name
            
            if (item.core.role == Role.FRIEND) {
                holder.tvRole.setBackgroundResource(R.drawable.shape_badge_gray_outline)
                holder.tvRole.setTextColor(context.getColor(R.color.gray_text))
            } else {
                holder.tvRole.setBackgroundResource(R.drawable.shape_badge_blue_outline)
                holder.tvRole.setTextColor(context.getColor(R.color.primary_blue))
            }

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
