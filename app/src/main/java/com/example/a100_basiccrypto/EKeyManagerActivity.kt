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
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import com.example.a100_basiccrypto.digitalkey.storage.SecureKeyStorageManager
import com.google.android.material.floatingactionbutton.ExtendedFloatingActionButton

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
        val sharedEKeys = allKeys.filter { 
            it.parentKeyID != null && it.parentKeyID!!.contentEquals(currentKeyId?.sliceArray(0 until 8)) 
        }
        
        rvEKeys.adapter = EKeyAdapter(sharedEKeys) { record ->
            showEKeyDetailDialog(record)
        }
    }

    private fun setupFab() {
        findViewById<ExtendedFloatingActionButton>(R.id.fab_add_ekey).setOnClickListener {
            val intent = Intent(this, ShareConfigActivity::class.java)
            startActivity(intent)
        }
    }

    private fun showEKeyDetailDialog(record: DigitalKeyRecord) {
        AlertDialog.Builder(this)
            .setTitle("eKey Details")
            .setMessage("Friendly Name: ${record.friendlyName}\nRole: ${record.role}\nUsage: ${if(record.usageLimit == 0) "Unlimited" else record.usageLimit.toString()}")
            .setPositiveButton("Edit Name") { _, _ ->
                Toast.makeText(this, "Edit feature coming soon", Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton("Delete") { _, _ ->
                showDeleteConfirmation(record)
            }
            .setNeutralButton("Close", null)
            .show()
    }

    private fun showDeleteConfirmation(record: DigitalKeyRecord) {
        AlertDialog.Builder(this)
            .setTitle("Delete eKey")
            .setMessage("Are you sure you want to revoke access for ${record.friendlyName}?")
            .setPositiveButton("Delete") { _, _ ->
                storageManager.deleteKey(record.keyID!!)
                refreshRecyclerView()
                Toast.makeText(this, "Key Revoked", Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton("Cancel", null)
            .show()
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
            holder.tvName.text = item.friendlyName.ifEmpty { "Guest Key" }
            holder.tvType.text = if (item.usageLimit == 1) "One-Time" else "Permanent/Timed"
            holder.itemView.setOnClickListener { onClick(item) }
        }

        override fun getItemCount() = items.size
    }
}
