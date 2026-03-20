package com.example.a100_basiccrypto

import android.app.Application
import com.example.a100_basiccrypto.digitalkey.core.GlobalDialogController

class MainApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        // Initialize Global Dialog Management
        GlobalDialogController.init(this)
    }
}
