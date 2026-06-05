package com.example.a100_basiccrypto

import android.app.Application
import com.example.a100_basiccrypto.di.AppContainer
import com.example.a100_basiccrypto.digitalkey.core.GlobalDialogController

class MainApplication : Application() {
    
    lateinit var container: AppContainer

    override fun onCreate() {
        super.onCreate()
        
        container = AppContainer(this)

        // Initialize Global Dialog Management
        GlobalDialogController.init(this)
    }
}
