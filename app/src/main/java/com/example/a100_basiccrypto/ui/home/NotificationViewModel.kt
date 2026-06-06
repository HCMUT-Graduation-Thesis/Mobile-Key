package com.example.a100_basiccrypto.ui.home

import androidx.lifecycle.ViewModel
import com.example.a100_basiccrypto.data.local.NotificationStore
import com.example.a100_basiccrypto.data.model.InvitationDetail
import kotlinx.coroutines.flow.StateFlow

class NotificationViewModel : ViewModel() {

    val notifications: StateFlow<List<NotificationStore.NotificationItem>> = NotificationStore.notifications

    fun selectInvitation(invitation: InvitationDetail) {
        NotificationStore.setPendingInvitation(invitation)
    }
}
