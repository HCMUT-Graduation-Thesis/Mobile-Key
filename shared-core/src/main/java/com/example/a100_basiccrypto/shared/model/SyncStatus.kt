package com.example.a100_basiccrypto.shared.model

/**
 * Common synchronization status for digital keys.
 * Used by both Device and Vehicle to track cloud sync state.
 */
enum class SyncStatus {
    SYNCED,
    PENDING_UPLOAD,
    PENDING_DOWNLOAD,
    PENDING_DELETE
}
