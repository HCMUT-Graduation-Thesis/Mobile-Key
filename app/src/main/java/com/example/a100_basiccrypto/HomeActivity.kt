package com.example.a100_basiccrypto

import android.content.Intent
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
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
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.google.android.material.chip.Chip
import com.google.android.material.floatingactionbutton.FloatingActionButton
import com.google.android.material.textfield.TextInputEditText
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach

class HomeActivity : AppCompatActivity() {

    private lateinit var rvKeys: RecyclerView
    private lateinit var fabAddKey: FloatingActionButton
    private lateinit var tvCount: TextView
    private lateinit var cvInvitationBanner: View
    private lateinit var btnViewInvitation: Button
    
    private val storageManager by lazy { SecureKeyStorageManager(this) }
    private lateinit var sharingViewModel: SharingViewModel

    private val keyAdapter = KeyAdapter { record ->
        val intent = Intent(this, ControlActivity::class.java)
        intent.putExtra("KEY_ID", record.keyID)
        startActivity(intent)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_home)

        // Init ViewModel
        sharingViewModel = ViewModelProvider(this, object : ViewModelProvider.Factory {
            override fun <T : ViewModel> create(modelClass: Class<T>): T {
                return SharingViewModel(DilithiumIdentityCryptoImpl(), storageManager) as T
            }
        })[SharingViewModel::class.java]

        setupToolbar()
        
        tvCount = findViewById(R.id.tv_count)
        rvKeys = findViewById(R.id.rv_keys)
        rvKeys.layoutManager = LinearLayoutManager(this)
        rvKeys.adapter = keyAdapter

        cvInvitationBanner = findViewById(R.id.cv_invitation_banner)
        btnViewInvitation = findViewById(R.id.btn_view_invitation)

        fabAddKey = findViewById(R.id.fab_add_key)
        fabAddKey.setOnClickListener {
            if (storageManager.getAllKeys().size >= 5) {
                Toast.makeText(this, "Maximum 5 keys allowed", Toast.LENGTH_SHORT).show()
            } else {
                startActivity(Intent(this, PairingActivity::class.java))
            }
        }

        findViewById<View>(R.id.btn_reset_all).setOnClickListener {
            storageManager.clearAll()
            sharingViewModel.clearMockServer()
            refreshList()
        }

        btnViewInvitation.setOnClickListener {
            showReceiveInvitationDialog()
        }

        observeViewModel()
    }

    private fun setupToolbar() {
        val toolbar = findViewById<Toolbar>(R.id.toolbar)
        toolbar.inflateMenu(R.menu.home_menu)
        toolbar.setOnMenuItemClickListener { item ->
            when (item.itemId) {
                R.id.action_simulate_push -> {
                    sharingViewModel.simulatePush()
                    true
                }
                R.id.action_clear_mock -> {
                    sharingViewModel.clearMockServer()
                    cvInvitationBanner.visibility = View.GONE
                    Toast.makeText(this, "Mock Server Cleared", Toast.LENGTH_SHORT).show()
                    true
                }
                else -> false
            }
        }
    }

    private fun observeViewModel() {
        // Listen for new invitations from Mock Server
        sharingViewModel.incomingInvitations
            .onEach { 
                runOnUiThread { cvInvitationBanner.visibility = View.VISIBLE }
            }
            .launchIn(lifecycleScope)

        // Listen for UI state changes
        lifecycleScope.launchWhenStarted {
            sharingViewModel.uiState.collect { state ->
                when (state) {
                    is SharingViewModel.SharingUiState.ReceivedInvitation -> {
                        refreshList()
                        cvInvitationBanner.visibility = View.GONE
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

    private fun showReceiveInvitationDialog() {
        lifecycleScope.launchWhenStarted {
            val ap = MockKeyServer.downloadAP()
            if (ap == null) {
                Toast.makeText(this@HomeActivity, "No invitation found", Toast.LENGTH_SHORT).show()
                return@launchWhenStarted
            }

            val dialog = BottomSheetDialog(this@HomeActivity)
            val view = LayoutInflater.from(this@HomeActivity).inflate(R.layout.dialog_receive_invitation, null)
            dialog.setContentView(view)

            // Extract info for display
            val tempRecord = SharingManager(DilithiumIdentityCryptoImpl(), storageManager).processIncomingInvitation(ap)
            
            view.findViewById<TextView>(R.id.tv_invitation_detail_owner).text = "Owner ID: ${tempRecord?.parentKeyID?.toHex() ?: "Unknown"}"
            view.findViewById<TextView>(R.id.tv_invitation_detail_perms).text = "Permissions: ${getPermissionsString(tempRecord?.permissions ?: 0)}"
            view.findViewById<TextView>(R.id.tv_invitation_detail_validity).text = "Expires: ${if (tempRecord?.validityEnd == 0L) "Never" else java.util.Date(tempRecord!!.validityEnd * 1000).toString()}"

            view.findViewById<Button>(R.id.btn_accept_invitation).setOnClickListener {
                val enteredCode = view.findViewById<TextInputEditText>(R.id.et_invitation_code).text.toString()
                
                // Verify Code locally for Mock
                val enteredHash = CryptoUtils.sha256(enteredCode.toByteArray())
                if (enteredHash.contentEquals(tempRecord?.invitationCodeHash)) {
                    sharingViewModel.processInvitation(ap)
                    dialog.dismiss()
                    Toast.makeText(this@HomeActivity, "Key Saved Successfully", Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(this@HomeActivity, "Invalid Invitation Code", Toast.LENGTH_SHORT).show()
                }
            }
            dialog.show()
        }
    }

    private fun getPermissionsString(perms: Int): String {
        val list = mutableListOf<String>()
        if (perms and SharingConstants.PERM_UNLOCK != 0) list.add("Unlock")
        if (perms and SharingConstants.PERM_LOCK != 0) list.add("Lock")
        if (perms and SharingConstants.PERM_START != 0) list.add("Start")
        if (perms and SharingConstants.PERM_TRUNK != 0) list.add("Trunk")
        if (perms and SharingConstants.PERM_PANIC != 0) list.add("Panic")
        return list.joinToString(", ")
    }

    override fun onResume() {
        super.onResume()
        refreshList()
    }

    private fun refreshList() {
        val keys = storageManager.getAllKeys()
        keyAdapter.submitList(keys)
        tvCount.text = "${keys.size}/5 Keys"
        fabAddKey.visibility = if (keys.size >= 5) View.GONE else View.VISIBLE
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
            holder.tvName.text = item.friendlyName.ifEmpty { "Digital Key" }
            holder.tvPlate.text = "Plate: ${item.carMetadata?.licensePlate ?: "--"}"
            
            // Status & Role Chips
            holder.chipRole.text = item.role.name
            holder.chipRole.setChipBackgroundColorResource(if (item.role == Role.OWNER) android.R.color.holo_blue_light else android.R.color.holo_green_light)
            
            if (item.keyState == KeyState.PROVISIONING) {
                holder.tvStatusDesc.visibility = View.VISIBLE
                holder.tvStatusDesc.text = "Ready to Activate (At Vehicle)"
                holder.tvStatusDesc.setTextColor(holder.itemView.context.getColor(android.R.color.holo_orange_dark))
            } else {
                holder.tvStatusDesc.visibility = View.GONE
            }
            
            holder.tvKeyId.text = "Key: ${item.keyID?.toHex()?.take(8) ?: "--"}"
            holder.tvModuleId.text = "MOD: ${item.moduleID?.toHex()?.take(4) ?: "--"}"
            
            holder.itemView.setOnClickListener { onClick(item) }
        }

        override fun getItemCount() = items.size

        class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
            val tvName: TextView = view.findViewById(R.id.tv_item_name)
            val tvPlate: TextView = view.findViewById(R.id.tv_item_plate)
            val chipRole: Chip = view.findViewById(R.id.chip_role_status)
            val tvStatusDesc: TextView = view.findViewById(R.id.tv_item_status_desc)
            val tvKeyId: TextView = view.findViewById(R.id.tv_item_keyid)
            val tvModuleId: TextView = view.findViewById(R.id.tv_item_moduleid)
        }
    }
}
