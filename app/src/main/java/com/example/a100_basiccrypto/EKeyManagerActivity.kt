package com.example.a100_basiccrypto

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
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.example.a100_basiccrypto.digitalkey.core.*
import com.example.a100_basiccrypto.digitalkey.storage.SecureKeyStorageManager
import com.example.a100_basiccrypto.shared.model.KeyState
import com.example.a100_basiccrypto.shared.model.Role
import com.google.android.material.floatingactionbutton.ExtendedFloatingActionButton
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach

class EKeyManagerActivity : AppCompatActivity() {

    private lateinit var rvEKeys: RecyclerView
    private val storageManager by lazy { SecureKeyStorageManager(this) }
    private var currentKeyId: ByteArray? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_ekey_manager)

        currentKeyId = intent.getByteArrayExtra("KEY_ID")
        
        setupToolbar()
        setupRecyclerView()
        setupFab()
        observeActivations()
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

    private fun observeActivations() {
        MockKeyServer.activationFlow
            .onEach { activatedAp ->
                // Check if any of our pending keys match this AP
                val allKeys = storageManager.getAllKeys()
                allKeys.forEach { key ->
                    if (key.core.keyState == KeyState.PENDING && key.attestationPackage.contentEquals(activatedAp)) {
                        key.core.keyState = KeyState.ACTIVE
                        storageManager.saveDigitalKey(key)
                        runOnUiThread {
                            refreshRecyclerView()
                            // Global notification could be used here instead of Toast
                            GlobalDialogController.showActionResult(this@EKeyManagerActivity, "EKEY ACTIVATION", true)
                        }
                    }
                }
            }
            .launchIn(lifecycleScope)
    }

    private fun showEKeyDetailDialog(record: DigitalKeyRecord) {
        val statusStr = when(record.core.keyState) {
            KeyState.PENDING -> "PENDING (Code: ${record.invitationCode})"
            KeyState.ACTIVE -> "ACTIVE"
            else -> record.core.keyState.name
        }

        AlertDialog.Builder(this)
            .setTitle("eKey Details")
            .setMessage("Friendly Name: ${record.friendlyName}\nStatus: $statusStr\nRole: ${record.core.role}\nUsage: ${if(record.core.usageLimit == 0) "Unlimited" else record.core.usageLimit.toString()}")
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
            .setMessage("Are you sure you want to revoke access for ${record.friendlyName}?")
            .setPositiveButton("Revoke") { _, _ ->
                storageManager.deleteKey(record.core.keyID!!)
                refreshRecyclerView()
                GlobalDialogController.showActionResult(this, "REVOKE ACCESS", true)
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
            holder.tvName.text = item.friendlyName.ifEmpty { "Guest Key" }
            
            val statusText = if (item.core.keyState == KeyState.PENDING) "PENDING [${item.invitationCode}]" else "ACTIVE"
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
