package com.example.a100_basiccrypto.ui.home

import android.graphics.Color
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.example.a100_basiccrypto.R
import com.example.a100_basiccrypto.data.local.NotificationStore
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach

class NotificationActivity : AppCompatActivity() {

    private lateinit var rvNotifications: RecyclerView
    private lateinit var tvEmpty: TextView
    private lateinit var viewModel: NotificationViewModel

    private val adapter = NotificationAdapter { item ->
        if (item.invitation != null && !item.isUsed) {
            viewModel.selectInvitation(item.invitation)
            finish()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_notification)

        viewModel = ViewModelProvider(this)[NotificationViewModel::class.java]

        setupToolbar()
        setupRecyclerView()
        observeNotifications()
    }

    private fun setupToolbar() {
        val toolbar = findViewById<Toolbar>(R.id.toolbar_notifications)
        setSupportActionBar(toolbar)
        toolbar.setNavigationOnClickListener { finish() }
    }

    private fun setupRecyclerView() {
        rvNotifications = findViewById(R.id.rv_notifications)
        tvEmpty = findViewById(R.id.tv_empty_notifications)
        rvNotifications.layoutManager = LinearLayoutManager(this)
        rvNotifications.adapter = adapter
    }

    private fun observeNotifications() {
        viewModel.notifications
            .onEach { notifications ->
                if (notifications.isEmpty()) {
                    rvNotifications.visibility = View.GONE
                    tvEmpty.visibility = View.VISIBLE
                } else {
                    rvNotifications.visibility = View.VISIBLE
                    tvEmpty.visibility = View.GONE
                    adapter.submitList(notifications)
                }
            }
            .launchIn(lifecycleScope)
    }

    class NotificationAdapter(private val onClick: (NotificationStore.NotificationItem) -> Unit) : 
        RecyclerView.Adapter<NotificationAdapter.ViewHolder>() {

        private var items = listOf<NotificationStore.NotificationItem>()

        fun submitList(newItems: List<NotificationStore.NotificationItem>) {
            items = newItems
            notifyDataSetChanged()
        }

        class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
            val tvTitle: TextView = view.findViewById(R.id.tv_notification_title)
            val tvMessage: TextView = view.findViewById(R.id.tv_notification_message)
            val tvStatus: TextView = view.findViewById(R.id.tv_notification_status)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
            val view = LayoutInflater.from(parent.context)
                .inflate(R.layout.item_notification, parent, false)
            return ViewHolder(view)
        }

        override fun onBindViewHolder(holder: ViewHolder, position: Int) {
            val item = items[position]
            holder.tvTitle.text = item.title
            holder.tvMessage.text = item.message
            
            if (item.isUsed) {
                holder.tvStatus.visibility = View.VISIBLE
                holder.tvStatus.text = "USED"
                holder.tvStatus.setTextColor(Color.GRAY)
                holder.itemView.alpha = 0.5f
            } else {
                holder.tvStatus.visibility = View.GONE
                holder.itemView.alpha = 1.0f
            }
            
            holder.itemView.setOnClickListener { onClick(item) }
        }

        override fun getItemCount() = items.size
    }
}
