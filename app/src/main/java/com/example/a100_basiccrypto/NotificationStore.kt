package com.example.a100_basiccrypto

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

object NotificationStore {
    data class NotificationItem(val title: String, val message: String, val timestamp: Long = System.currentTimeMillis())

    private val _notifications = MutableStateFlow<List<NotificationItem>>(emptyList())
    val notifications: StateFlow<List<NotificationItem>> = _notifications

    fun addNotification(title: String, message: String) {
        val newList = _notifications.value.toMutableList()
        newList.add(0, NotificationItem(title, message))
        _notifications.value = newList
    }

    fun clear() {
        _notifications.value = emptyList()
    }
}
