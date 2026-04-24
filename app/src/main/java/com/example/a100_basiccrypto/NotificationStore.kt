package com.example.a100_basiccrypto

import com.example.a100_basiccrypto.digitalkey.core.ShareInvitation
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map

object NotificationStore {
    data class NotificationItem(
        val title: String, 
        val message: String, 
        val invitation: ShareInvitation? = null,
        var isUsed: Boolean = false,
        var attempts: Int = 0, // Track PIN entry attempts
        val timestamp: Long = System.currentTimeMillis()
    )

    private val _notifications = MutableStateFlow<List<NotificationItem>>(emptyList())
    val notifications: StateFlow<List<NotificationItem>> = _notifications

    // StateFlow to track if there are any unread/unused invitations
    val hasUnread: StateFlow<Boolean> = _notifications.map { list ->
        list.any { !it.isUsed && it.attempts < 3 }
    }.run {
        val flow = MutableStateFlow(false)
        // We'll update this manually in addNotification/markAsUsed for simplicity in this mock
        flow
    }
    
    // A simpler way for the badge logic in a singleton
    private val _unreadCount = MutableStateFlow(false)
    val unreadBadgeVisible: StateFlow<Boolean> = _unreadCount

    private val _pendingInvitation = MutableStateFlow<ShareInvitation?>(null)
    val pendingInvitation: StateFlow<ShareInvitation?> = _pendingInvitation

    fun addNotification(title: String, message: String, invitation: ShareInvitation? = null) {
        val newList = _notifications.value.toMutableList()
        if (newList.any { it.invitation == invitation }) return
        
        newList.add(0, NotificationItem(title, message, invitation))
        _notifications.value = newList
        updateBadge()
    }

    fun markAsUsed(invitation: ShareInvitation) {
        val newList = _notifications.value.map { 
            if (it.invitation == invitation) it.copy(isUsed = true) else it 
        }
        _notifications.value = newList
        updateBadge()
    }

    fun incrementAttempts(invitation: ShareInvitation): Int {
        var currentAttempts = 0
        val newList = _notifications.value.map { 
            if (it.invitation == invitation) {
                val newCount = it.attempts + 1
                currentAttempts = newCount
                val used = if (newCount >= 3) true else it.isUsed
                it.copy(attempts = newCount, isUsed = used)
            } else it 
        }
        _notifications.value = newList
        updateBadge()
        return currentAttempts
    }

    private fun updateBadge() {
        _unreadCount.value = _notifications.value.any { !it.isUsed && it.attempts < 3 }
    }

    fun setPendingInvitation(invitation: ShareInvitation?) {
        _pendingInvitation.value = invitation
    }

    fun clear() {
        _notifications.value = emptyList()
        updateBadge()
    }
}
