package com.example.a100_basiccrypto.digitalkey.core

import android.app.Activity
import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.widget.Button
import android.widget.ImageView
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import com.example.a100_basiccrypto.R
import com.example.a100_basiccrypto.digitalkey.nfc.MyHostApduService
import com.google.android.material.bottomsheet.BottomSheetDialog

/**
 * Manages global dialogs across the entire application.
 * Uses ActivityLifecycleCallbacks to track the foreground activity.
 */
object GlobalDialogController : Application.ActivityLifecycleCallbacks {

    private var currentActivity: Activity? = null
    private var authDialog: AlertDialog? = null
    private val handler = Handler(Looper.getMainLooper())

    fun init(app: Application) {
        app.registerActivityLifecycleCallbacks(this)
        
        val filter = IntentFilter().apply {
            addAction(MyHostApduService.ACTION_NFC_RESULT)
            addAction(MyHostApduService.LOG_ACTION)
        }
        
        app.registerReceiver(object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                // Check if activity is still valid before processing
                val activity = currentActivity
                if (activity == null || activity.isFinishing || activity.isDestroyed) return

                when (intent.action) {
                    MyHostApduService.ACTION_NFC_RESULT -> {
                        val actionName = intent.getStringExtra("action_name") ?: ""
                        val isSuccess = intent.getBooleanExtra("is_success", false)
                        showActionResult(activity, actionName, isSuccess)
                    }
                    MyHostApduService.LOG_ACTION -> {
                        val message = intent.getStringExtra("log_message") ?: ""
                        handleNfcLogs(activity, message)
                    }
                }
            }
        }, filter, Context.RECEIVER_EXPORTED)
    }

    private fun handleNfcLogs(activity: Activity, message: String) {
        if (!MyHostApduService.isPairingModeEnabled && message.contains("STD: Phase 1")) {
            showAuthenticatingDialog(activity)
        }
        
        if (message.contains("Transaction Finalized") || message.contains("Session Timeout") || message.contains("STD: Phase 4")) {
            authDialog?.dismiss()
            authDialog = null
        }
    }

    private fun showAuthenticatingDialog(activity: Activity) {
        if (activity.isFinishing || activity.isDestroyed) return
        if (authDialog?.isShowing == true) return
        
        try {
            val builder = AlertDialog.Builder(activity)
            val view = activity.layoutInflater.inflate(R.layout.dialog_standard_authenticating, null)
            builder.setView(view)
            builder.setCancelable(false)
            authDialog = builder.create()
            authDialog?.window?.setBackgroundDrawableResource(android.R.color.transparent)
            authDialog?.show()
        } catch (e: Exception) {
            Log.e("GlobalDialog", "Failed to show auth dialog: ${e.message}")
        }
    }

    fun showActionResult(activity: Activity, action: String, isSuccess: Boolean) {
        if (activity.isFinishing || activity.isDestroyed) return
        authDialog?.dismiss()
        
        try {
            val dialog = BottomSheetDialog(activity)
            val view = activity.layoutInflater.inflate(R.layout.dialog_action_result, null)
            dialog.setContentView(view)

            val ivIcon = view.findViewById<ImageView>(R.id.iv_result_icon)
            val tvTitle = view.findViewById<TextView>(R.id.tv_result_title)
            val tvMessage = view.findViewById<TextView>(R.id.tv_result_message)
            val btnOk = view.findViewById<Button>(R.id.btn_result_ok)

            if (isSuccess) {
                ivIcon.setImageResource(android.R.drawable.checkbox_on_background)
                ivIcon.setColorFilter(activity.getColor(R.color.success_green))
                tvTitle.text = "Success"
                tvTitle.setTextColor(activity.getColor(R.color.success_green))
                tvMessage.text = "Command [$action] executed successfully."
            } else {
                ivIcon.setImageResource(android.R.drawable.ic_delete)
                ivIcon.setColorFilter(activity.getColor(R.color.error_red))
                tvTitle.text = "Action Denied"
                tvTitle.setTextColor(activity.getColor(R.color.error_red))
                tvMessage.text = "Command [$action] failed.\nSystem desynchronized or permission denied."
            }

            val dismissRunnable = Runnable { if (dialog.isShowing) dialog.dismiss() }
            handler.postDelayed(dismissRunnable, 2000)

            btnOk.setOnClickListener { 
                handler.removeCallbacks(dismissRunnable)
                dialog.dismiss() 
            }
            dialog.show()
        } catch (e: Exception) {
            Log.e("GlobalDialog", "Failed to show result dialog: ${e.message}")
        }
    }

    override fun onActivityResumed(activity: Activity) { currentActivity = activity }
    override fun onActivityPaused(activity: Activity) { if (currentActivity == activity) currentActivity = null }
    override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) { currentActivity = activity }
    override fun onActivityStarted(activity: Activity) { currentActivity = activity }
    override fun onActivityStopped(activity: Activity) { if (currentActivity == activity) currentActivity = null }
    override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}
    override fun onActivityDestroyed(activity: Activity) {
        if (currentActivity == activity) {
            authDialog?.dismiss()
            authDialog = null
            currentActivity = null
        }
    }
}
