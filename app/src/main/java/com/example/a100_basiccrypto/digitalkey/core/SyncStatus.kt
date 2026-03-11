package com.example.a100_basiccrypto.digitalkey.core

/**
 * Sync status with the server.
 */
enum class SyncStatus {
    SYNCED,
    PENDING_UPLOAD,
    PENDING_DOWNLOAD,
    PENDING_DELETE
}
