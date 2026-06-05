package com.example.a100_basiccrypto.di

import android.content.Context
import com.example.a100_basiccrypto.data.api.KeyServerApi
import com.example.a100_basiccrypto.data.api.mock.MockKeyServer
import com.example.a100_basiccrypto.data.local.IdentityStorageManager
import com.example.a100_basiccrypto.data.repository.AuthRepository
import com.example.a100_basiccrypto.data.repository.KeyRepository
import com.example.a100_basiccrypto.digitalkey.core.AuthManager
import com.example.a100_basiccrypto.digitalkey.storage.SecureKeyStorageManager
import com.example.a100_basiccrypto.shared.crypto.DilithiumIdentityCryptoImpl

class AppContainer(private val context: Context) {
    
    // Low-level dependencies
    val authManager: AuthManager by lazy { AuthManager(context) }
    val storageManager: SecureKeyStorageManager by lazy { SecureKeyStorageManager(context) }
    val identityStorageManager: IdentityStorageManager by lazy { IdentityStorageManager(context) }
    val identityCrypto: DilithiumIdentityCryptoImpl by lazy { DilithiumIdentityCryptoImpl() }
    
    // API
    val keyServerApi: KeyServerApi = MockKeyServer
    
    // Repositories
    val authRepository: AuthRepository by lazy {
        AuthRepository(keyServerApi, authManager, identityStorageManager, identityCrypto)
    }
    
    val keyRepository: KeyRepository by lazy {
        KeyRepository(keyServerApi)
    }
}
