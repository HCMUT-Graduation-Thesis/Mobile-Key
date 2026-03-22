package com.example.a100_basiccrypto

import com.example.a100_basiccrypto.digitalkey.core.ShareInvitation
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

object NotificationStore {
    data class NotificationItem(
        val title: String, 
        val message: String, 
        val invitation: ShareInvitation? = null,
        var isUsed: Boolean = false, // Thêm trạng thái đã sử dụng
        val timestamp: Long = System.currentTimeMillis()
    )

    private val _notifications = MutableStateFlow<List<NotificationItem>>(emptyList())
    val notifications: StateFlow<List<NotificationItem>> = _notifications

    private val _pendingInvitation = MutableStateFlow<ShareInvitation?>(null)
    val pendingInvitation: StateFlow<ShareInvitation?> = _pendingInvitation

    fun addNotification(title: String, message: String, invitation: ShareInvitation? = null) {
        val newList = _notifications.value.toMutableList()
        if (newList.any { it.invitation == invitation }) return
        
        newList.add(0, NotificationItem(title, message, invitation))
        _notifications.value = newList
    }

    // Thay thế hàm xóa bằng hàm đánh dấu đã sử dụng
    fun markAsUsed(invitation: ShareInvitation) {
        val newList = _notifications.value.map { 
            if (it.invitation == invitation) it.copy(isUsed = true) else it 
        }
        _notifications.value = newList
    }

    fun setPendingInvitation(invitation: ShareInvitation?) {
        _pendingInvitation.value = invitation
    }

    fun clear() {
        _notifications.value = emptyList()
    }
}
