package com.example.a100_basiccrypto

import android.content.Intent
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord
import com.example.a100_basiccrypto.digitalkey.crypto.CryptoUtils.toHex
import com.example.a100_basiccrypto.digitalkey.storage.SecureKeyStorageManager
import com.google.android.material.floatingactionbutton.FloatingActionButton

class HomeActivity : AppCompatActivity() {

    private lateinit var rvKeys: RecyclerView
    private lateinit var fabAddKey: FloatingActionButton
    private lateinit var tvCount: TextView
    private val storageManager by lazy { SecureKeyStorageManager(this) }
    private val keyAdapter = KeyAdapter { record ->
        val intent = Intent(this, ControlActivity::class.java)
        intent.putExtra("KEY_ID", record.keyID)
        startActivity(intent)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_home)

        tvCount = findViewById(R.id.tv_count)
        rvKeys = findViewById(R.id.rv_keys)
        rvKeys.layoutManager = LinearLayoutManager(this)
        rvKeys.adapter = keyAdapter

        fabAddKey = findViewById(R.id.fab_add_key)
        fabAddKey.setOnClickListener {
            if (storageManager.getAllKeys().size >= 3) {
                Toast.makeText(this, "Maximum 3 keys allowed", Toast.LENGTH_SHORT).show()
            } else {
                startActivity(Intent(this, PairingActivity::class.java))
            }
        }

        findViewById<View>(R.id.btn_reset_all).setOnClickListener {
            storageManager.clearAll()
            refreshList()
        }
    }

    override fun onResume() {
        super.onResume()
        refreshList()
    }

    private fun refreshList() {
        val keys = storageManager.getAllKeys()
        keyAdapter.submitList(keys)
        tvCount.text = "${keys.size}/3 Keys"
        fabAddKey.visibility = if (keys.size >= 3) View.GONE else View.VISIBLE
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
            holder.tvStatus.text = "Status: ${item.keyState.name}"
            holder.tvPlate.text = "Plate: ${item.carMetadata?.licensePlate ?: "--"}"
            
            // Hiển thị KeyID và ModuleID dưới dạng Hex để đối chiếu với Reader
            // KeyID cũng là ByteArray nên dùng .toHex()
            holder.tvKeyId.text = "KeyID: ${item.keyID?.toHex() ?: "--"}"
            holder.tvModuleId.text = "ModuleID: ${item.moduleID?.toHex() ?: "--"}"
            
            holder.itemView.setOnClickListener { onClick(item) }
        }

        override fun getItemCount() = items.size

        class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
            val tvName: TextView = view.findViewById(R.id.tv_item_name)
            val tvStatus: TextView = view.findViewById(R.id.tv_item_status)
            val tvPlate: TextView = view.findViewById(R.id.tv_item_plate)
            val tvKeyId: TextView = view.findViewById(R.id.tv_item_keyid)
            val tvModuleId: TextView = view.findViewById(R.id.tv_item_moduleid)
        }
    }
}
