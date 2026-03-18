package com.example.a100_basiccrypto

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach

class NotificationActivity : AppCompatActivity() {

    private lateinit var rvNotifications: RecyclerView
    private lateinit var tvEmpty: TextView
    private val adapter = NotificationAdapter()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_notification)

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
        NotificationStore.notifications
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

    class NotificationAdapter : RecyclerView.Adapter<NotificationAdapter.ViewHolder>() {

        private var items = listOf<NotificationStore.NotificationItem>()

        fun submitList(newItems: List<NotificationStore.NotificationItem>) {
            items = newItems
            notifyDataSetChanged()
        }

        class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
            val tvTitle: TextView = view.findViewById(android.R.id.text1)
            val tvMessage: TextView = view.findViewById(android.R.id.text2)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
            val view = LayoutInflater.from(parent.context)
                .inflate(android.R.layout.simple_list_item_2, parent, false)
            return ViewHolder(view)
        }

        override fun onBindViewHolder(holder: ViewHolder, position: Int) {
            val item = items[position]
            holder.tvTitle.text = item.title
            holder.tvTitle.setTextColor(holder.itemView.context.getColor(R.color.primary_blue))
            holder.tvMessage.text = item.message
            holder.tvMessage.setTextColor(holder.itemView.context.getColor(R.color.white))
        }

        override fun getItemCount() = items.size
    }
}
