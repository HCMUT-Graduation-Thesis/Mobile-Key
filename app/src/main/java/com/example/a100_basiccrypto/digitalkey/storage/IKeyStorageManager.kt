package com.example.a100_basiccrypto.digitalkey.storage

import com.example.a100_basiccrypto.digitalkey.core.DigitalKeyRecord

interface IKeyStorageManager {
    fun saveDigitalKey(record: DigitalKeyRecord)
    fun getDigitalKey(): DigitalKeyRecord?
    fun updateTransactionCounter(counter: Int)
    fun clearAll()
}
