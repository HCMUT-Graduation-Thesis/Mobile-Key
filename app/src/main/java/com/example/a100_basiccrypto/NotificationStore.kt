package com.example.a100_basiccrypto

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

object NotificationStore {
    data class NotificationItem(
        val title: String, 
        val message: String, 
        val ap: ByteArray? = null, // Lưu gói AP kèm theo
        val timestamp: Long = System.currentTimeMillis()
    )

    private val _notifications = MutableStateFlow<List<NotificationItem>>(emptyList())
    val notifications: StateFlow<List<NotificationItem>> = _notifications

    private val _pendingInvitation = MutableStateFlow<ByteArray?>(null)
    val pendingInvitation: StateFlow<ByteArray?> = _pendingInvitation

    fun addNotification(title: String, message: String, ap: ByteArray? = null) {
        val newList = _notifications.value.toMutableList()
        newList.add(0, NotificationItem(title, message, ap))
        _notifications.value = newList
    }

    fun setPendingInvitation(ap: ByteArray?) {
        _pendingInvitation.value = ap
    }

    fun clear() {
        _notifications.value = emptyList()
    }
}
