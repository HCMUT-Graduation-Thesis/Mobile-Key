package com.example.a100_basiccrypto

import android.util.Log
import com.example.a100_basiccrypto.digitalkey.core.ShareInvitation
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.*

object NotificationStore {
    private const val TAG = "NotificationStore"
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
        Log.d(TAG, "👤 [STORE] Setting current user to: $email")
        currentUserEmail.value = email
    }

    private val _unreadCount = MutableStateFlow(false)
    val unreadBadgeVisible: StateFlow<Boolean> = _unreadCount

    private val _pendingInvitation = MutableStateFlow<ShareInvitation?>(null)
    val pendingInvitation: StateFlow<ShareInvitation?> = _pendingInvitation

    init {
        // Automatically update the badge whenever the filtered notifications change
        notifications.onEach { list ->
            val unread = list.any { !it.isUsed && it.attempts < 3 }
            Log.v(TAG, "🔔 [STORE] Updating badge for ${currentUserEmail.value}. Unread exists: $unread")
            _unreadCount.value = unread
        }.launchIn(scope)
    }

    fun addNotification(ownerEmail: String, title: String, message: String, invitation: ShareInvitation? = null) {
        Log.i(TAG, "✉️ [STORE] Adding notification for $ownerEmail: $title")
        val newList = _notifications.value.toMutableList()
        // Prevent duplicates for the same invitation for the same user
        if (newList.any { it.invitation == invitation && it.ownerEmail == ownerEmail }) {
            Log.d(TAG, "⚠️ [STORE] Duplicate notification ignored for $ownerEmail.")
            return
        }
        
        newList.add(0, NotificationItem(ownerEmail, title, message, invitation))
        _notifications.value = newList
    }

    fun markAsUsed(invitation: ShareInvitation) {
        Log.d(TAG, "✅ [STORE] Marking invitation as used: ${invitation.friendlyName}")
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
                Log.w(TAG, "🔢 [STORE] PIN attempt $newCount/3 for ${invitation.friendlyName}")
                it.copy(attempts = newCount, isUsed = used)
            } else it 
        }
        _notifications.value = newList
        return currentAttempts
    }

    fun setPendingInvitation(invitation: ShareInvitation?) {
        Log.v(TAG, "📌 [STORE] Setting pending invitation: ${invitation?.friendlyName ?: "null"}")
        _pendingInvitation.value = invitation
    }

    fun clearAll() {
        Log.w(TAG, "🗑️ [STORE] Clearing all notifications.")
        _notifications.value = emptyList()
    }
}
