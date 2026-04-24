package com.example.a100_basiccrypto

import com.example.a100_basiccrypto.digitalkey.core.ShareInvitation
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.*

object NotificationStore {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    data class NotificationItem(
        val ownerEmail: String, // Link notification to a specific user
        val title: String, 
        val message: String, 
        val invitation: ShareInvitation? = null,
        var isUsed: Boolean = false,
        var attempts: Int = 0, 
        val timestamp: Long = System.currentTimeMillis()
    )

    private val _notifications = MutableStateFlow<List<NotificationItem>>(emptyList())
    private val currentUserEmail = MutableStateFlow<String>("")

    /**
     * Public Flow that provides notifications ONLY for the current user.
     */
    val notifications: StateFlow<List<NotificationItem>> = combine(_notifications, currentUserEmail) { list, email ->
        if (email.isEmpty()) emptyList() 
        else list.filter { it.ownerEmail.equals(email, ignoreCase = true) }
    }.stateIn(scope, SharingStarted.Eagerly, emptyList())

    /**
     * Call this when user logs in or switches account
     */
    fun setCurrentUser(email: String) {
        currentUserEmail.value = email
    }

    private val _unreadCount = MutableStateFlow(false)
    val unreadBadgeVisible: StateFlow<Boolean> = _unreadCount

    private val _pendingInvitation = MutableStateFlow<ShareInvitation?>(null)
    val pendingInvitation: StateFlow<ShareInvitation?> = _pendingInvitation

    init {
        // Automatically update the badge whenever the filtered notifications change
        notifications.onEach { list ->
            _unreadCount.value = list.any { !it.isUsed && it.attempts < 3 }
        }.launchIn(scope)
    }

    fun addNotification(ownerEmail: String, title: String, message: String, invitation: ShareInvitation? = null) {
        val newList = _notifications.value.toMutableList()
        // Prevent duplicates for the same invitation for the same user
        if (newList.any { it.invitation == invitation && it.ownerEmail == ownerEmail }) return
        
        newList.add(0, NotificationItem(ownerEmail, title, message, invitation))
        _notifications.value = newList
    }

    fun markAsUsed(invitation: ShareInvitation) {
        val newList = _notifications.value.map { 
            if (it.invitation == invitation) it.copy(isUsed = true) else it 
        }
        _notifications.value = newList
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
        return currentAttempts
    }

    fun setPendingInvitation(invitation: ShareInvitation?) {
        _pendingInvitation.value = invitation
    }

    fun clearAll() {
        _notifications.value = emptyList()
    }
}
