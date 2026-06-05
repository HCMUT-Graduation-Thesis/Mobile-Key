package com.example.a100_basiccrypto.ui.keycontrol

import android.content.Intent
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.example.a100_basiccrypto.MainApplication
import com.example.a100_basiccrypto.NotificationStore
import com.example.a100_basiccrypto.R
import com.example.a100_basiccrypto.digitalkey.core.*
import com.example.a100_basiccrypto.shared.model.KeyState
import com.example.a100_basiccrypto.shared.model.Role
import com.google.android.material.floatingactionbutton.ExtendedFloatingActionButton
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

class EKeyManagerActivity : AppCompatActivity() {

    private lateinit var rvEKeys: RecyclerView
    private val container by lazy { (application as MainApplication).container }
    private val storageManager by lazy { container.storageManager }
    private val authManager by lazy { container.authManager }
    private lateinit var sharingViewModel: SharingViewModel
    private var currentKeyId: ByteArray? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_ekey_manager)

        currentKeyId = intent.getByteArrayExtra("KEY_ID")
        
        initViewModel()
        setupToolbar()
        setupRecyclerView()
        setupFab()
        observeViewModel()
    }

    private fun initViewModel() {
        sharingViewModel = ViewModelProvider(this, object : ViewModelProvider.Factory {
            override fun <T : ViewModel> create(modelClass: Class<T>): T {
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
    }

    private fun setupToolbar() {
        val toolbar = findViewById<Toolbar>(R.id.toolbar_ekeys)
        setSupportActionBar(toolbar)
        toolbar.setNavigationOnClickListener { finish() }
    }

    private fun setupRecyclerView() {
        rvEKeys = findViewById(R.id.rv_ekeys)
        rvEKeys.layoutManager = LinearLayoutManager(this)
        refreshRecyclerView()
    }

    private fun refreshRecyclerView() {
        val allKeys = storageManager.getAllKeys()
        // Filter keys that belong to this Owner key
        val sharedEKeys = allKeys.filter { 
            it.core.parentKeyID != null && it.core.parentKeyID!!.contentEquals(currentKeyId?.sliceArray(0 until 8))
        }
        
        rvEKeys.adapter = EKeyAdapter(sharedEKeys) { record ->
            showEKeyDetailDialog(record)
        }
    }

    private fun setupFab() {
        findViewById<ExtendedFloatingActionButton>(R.id.fab_add_ekey).setOnClickListener {
            val intent = Intent(this, ShareConfigActivity::class.java)
            intent.putExtra("OWNER_KEY_ID", currentKeyId)
            startActivity(intent)
        }
    }

    private fun observeViewModel() {
        lifecycleScope.launch {
            sharingViewModel.events.collectLatest { event ->
                when (event) {
                    is SharingViewModel.SharingEvent.RemoteActivationSuccess -> {
                        refreshRecyclerView()
                        GlobalDialogController.showActionResult(this@EKeyManagerActivity, "EKEY ACTIVATION", true)
                    }
                    is SharingViewModel.SharingEvent.LocalRevokeSuccess -> {
                        refreshRecyclerView()
                        GlobalDialogController.showActionResult(this@EKeyManagerActivity, "REVOKE ACCESS", true)
                    }
                    else -> {}
                }
            }
        }
    }

    private fun showEKeyDetailDialog(record: DigitalKeyRecord) {
        val statusStr = when(record.core.keyState) {
            KeyState.PENDING -> "PENDING (Code: ${record.invitationCode})"
            KeyState.ACTIVE -> "ACTIVE"
            KeyState.PROVISIONING -> "PROVISIONING"
            else -> record.core.keyState.name
        }

        AlertDialog.Builder(this)
            .setTitle("eKey Details")
            .setMessage("Key Holder: ${record.keyHolderName}\nVehicle: ${record.friendlyName}\nStatus: $statusStr\nRole: ${record.core.role}\nUsage: ${if(record.core.usageLimit == 0) "Unlimited" else record.core.usageLimit.toString()}")
            .setPositiveButton("Edit Name") { _, _ ->
                Toast.makeText(this, "Edit feature coming soon", Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton("Revoke") { _, _ ->
                showDeleteConfirmation(record)
            }
            .setNeutralButton("Close", null)
            .show()
    }

    private fun showDeleteConfirmation(record: DigitalKeyRecord) {
        AlertDialog.Builder(this)
            .setTitle("Revoke Access")
            .setMessage("Are you sure you want to revoke access for ${record.keyHolderName}?")
            .setPositiveButton("Revoke") { _, _ ->
                sharingViewModel.revokeKey(record)
            }
            .setNegativeButton("Cancel", null)
            .create().apply {
                show()
                getButton(AlertDialog.BUTTON_POSITIVE).setTextColor(getColor(R.color.error_red))
            }
    }

    override fun onResume() {
        super.onResume()
        refreshRecyclerView()
    }

    class EKeyAdapter(private val items: List<DigitalKeyRecord>, private val onClick: (DigitalKeyRecord) -> Unit) :
        RecyclerView.Adapter<EKeyAdapter.ViewHolder>() {

        class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
            val tvName: TextView = view.findViewById(R.id.tv_ekey_name)
            val tvType: TextView = view.findViewById(R.id.tv_ekey_type)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
            val view = LayoutInflater.from(parent.context).inflate(R.layout.item_ekey, parent, false)
            return ViewHolder(view)
        }

        override fun onBindViewHolder(holder: ViewHolder, position: Int) {
            val item = items[position]
            val context = holder.itemView.context
            // Display Holder Nickname instead of car name
            holder.tvName.text = item.keyHolderName.ifEmpty { "Guest Key" }
            
            val statusText = when(item.core.keyState) {
                KeyState.PENDING -> "PENDING [${item.invitationCode}]"
                KeyState.PROVISIONING -> "PROVISIONING"
                KeyState.ACTIVE -> "ACTIVE"
                else -> item.core.keyState.name
            }
            holder.tvType.text = "${if (item.core.usageLimit == 1) "One-Time" else "Normal"} | $statusText"
            
            if (item.core.keyState == KeyState.PENDING) {
                holder.tvName.setTextColor(context.getColor(R.color.gray_text))
            } else {
                holder.tvName.setTextColor(context.getColor(R.color.white))
            }

            holder.itemView.setOnClickListener { onClick(item) }
        }

        override fun getItemCount() = items.size
    }
}
