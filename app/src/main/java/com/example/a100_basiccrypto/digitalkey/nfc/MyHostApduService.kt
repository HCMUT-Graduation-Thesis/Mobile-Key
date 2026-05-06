package com.example.a100_basiccrypto.digitalkey.nfc

import android.content.Intent
import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import com.example.a100_basiccrypto.digitalkey.core.AuthManager
import com.example.a100_basiccrypto.shared.link.LogicalFrame
import com.example.a100_basiccrypto.shared.link.LogicalResponse
import com.example.a100_basiccrypto.shared.link.TransactionRouter
import com.example.a100_basiccrypto.shared.link.ITransactionHandler
import com.example.a100_basiccrypto.shared.command.MessageConstants.Class
import com.example.a100_basiccrypto.shared.command.MessageConstants.Fast
import com.example.a100_basiccrypto.shared.command.MessageConstants.Admin
import com.example.a100_basiccrypto.shared.command.MessageConstants.FriendPairing
import com.example.a100_basiccrypto.shared.command.MessageConstants.Status
import com.example.a100_basiccrypto.shared.crypto.DilithiumIdentityCryptoImpl
import com.example.a100_basiccrypto.shared.physical.NfcConstants
import com.example.a100_basiccrypto.digitalkey.storage.PasswordManager
import com.example.a100_basiccrypto.digitalkey.storage.SecureKeyStorageManager
import com.example.a100_basiccrypto.digitalkey.transactions.FastTransaction
import com.example.a100_basiccrypto.digitalkey.transactions.OwnerPairingTransaction
import com.example.a100_basiccrypto.digitalkey.transactions.StandardTransaction

/**
 * Optimized HostApduService using NfcPassiveTransport and TransactionRouter.
 * Updated: Account-aware logic to prevent unauthorized access from logged-out users.
 */
class MyHostApduService : HostApduService() {

    companion object {
        private const val TAG = "NfcDigitalKey"
        const val LOG_ACTION = "com.example.a100_basiccrypto.LOG_ACTION"
        const val ACTION_NFC_RESULT = "com.example.a100_basiccrypto.NFC_RESULT"
        
        @Volatile
        var isPairingModeEnabled: Boolean = false

        @Volatile
        var friendPairingHandler: ITransactionHandler? = null
    }

    private val storageManager by lazy { SecureKeyStorageManager(applicationContext) }
    private val authManager by lazy { AuthManager(applicationContext) }
    private val identityCrypto = DilithiumIdentityCryptoImpl()
    
    private val nfcTransport = NfcPassiveTransport()

    private val router: TransactionRouter by lazy {
        val pairingHandler = OwnerPairingTransaction(
            context = applicationContext,
            identityCrypto = identityCrypto,
            storageManager = storageManager,
            authManager = authManager,
            passwordProvider = { PasswordManager.getPassword(applicationContext) },
            onLog = { sendLogToGui(it) }
        )
        val fastHandler = FastTransaction(
            storageManager = storageManager,
            authManager = authManager,
            onLog = { sendLogToGui(it) }
        )
        val standardHandler = StandardTransaction(
            identityCrypto = identityCrypto,
            storageManager = storageManager,
            authManager = authManager,
            passwordProvider = { PasswordManager.getPassword(applicationContext) },
            onLog = { sendLogToGui(it) }
        )
        TransactionRouter(
            pairingHandler = pairingHandler,
            fastHandler = fastHandler,
            standardHandler = standardHandler,
            friendPairingHandler = friendPairingHandler
        ).apply {
            nfcTransport.setCallback(this)
        }
    }

    private val timeoutHandler = Handler(Looper.getMainLooper())
    private val timeoutRunnable = Runnable { handleTimeout() }

    override fun processCommandApdu(commandApdu: ByteArray?, extras: Bundle?): ByteArray {
        if (commandApdu == null || commandApdu.size < 2) return NfcConstants.SW_INTERNAL_ERROR

        // SECURITY CHECK: Ensure a user is logged in before processing any car commands
        if (!authManager.isLoggedIn()) {
            Log.w(TAG, "NFC Access Denied: No user logged in.")
            return NfcConstants.SW_UNKNOWN_CMD
        }

        val cla = commandApdu[0]
        val ins = commandApdu[1]
        
        if ((cla == Class.OWNER_PAIRING || cla == 0x80.toByte()) && !isPairingModeEnabled) {
            return NfcConstants.SW_UNKNOWN_CMD
        }

        if (cla == NfcConstants.CLA_ISO && ins == 0xA4.toByte()) {
            resetSession()
            sendLogToGui("System: Reader Connected.")
            return NfcConstants.SW_SUCCESS
        }

        if (ins == NfcConstants.INS_GET_NEXT_CHUNK) {
            val chunkIndex = if (commandApdu.size >= 3) commandApdu[2].toInt() and 0xFF else 0
            return nfcTransport.getNextChunk(chunkIndex)
        }

        resetTimeoutTimer()

        return nfcTransport.onApduReceived(commandApdu) { frame, response ->
            handleActionBroadcasts(frame, response)
        }
    }

    private fun handleActionBroadcasts(frame: LogicalFrame, response: LogicalResponse) {
        val actionName = when {
            frame.msgClass == Class.FAST_ACTION && frame.msgId == Fast.INS_UNLOCK -> "UNLOCK"
            frame.msgClass == Class.FAST_ACTION && frame.msgId == Fast.INS_LOCK -> "LOCK"
            frame.msgClass == Class.ENGINE_OP && frame.msgId == Fast.INS_START_ENGINE -> "START ENGINE"
            frame.msgClass == Class.ENGINE_OP && frame.msgId == Fast.INS_STOP_ENGINE -> "STOP ENGINE"
            frame.msgClass == Class.ADMIN && frame.msgId == Admin.PHASE_FINAL_COMMIT -> "RECOVERY & ACTION"
            frame.msgClass == Class.FRIEND_PAIRING && frame.msgId == FriendPairing.PHASE_COMMIT -> "FRIEND PAIRING"
            else -> null
        }

        if (actionName != null) {
            val isSuccess = response.status == Status.SUCCESS
            broadcastResultToActivity(actionName, isSuccess)
        }
    }

    private fun broadcastResultToActivity(actionName: String, isSuccess: Boolean) {
        val intent = Intent(ACTION_NFC_RESULT).apply {
            putExtra("action_name", actionName)
            putExtra("is_success", isSuccess)
            setPackage(packageName)
        }
        sendBroadcast(intent)
    }

    private fun sendLogToGui(message: String) {
        val intent = Intent(LOG_ACTION).apply {
            putExtra("log_message", message)
            setPackage(packageName)
        }
        sendBroadcast(intent)
    }

    private fun resetSession() {
        timeoutHandler.removeCallbacks(timeoutRunnable)
        timeoutHandler.postDelayed(timeoutRunnable, NfcConstants.TRANSACTION_TIMEOUT_MS)
        nfcTransport.reset()
        router.resetAll()
    }

    private fun resetTimeoutTimer() {
        timeoutHandler.removeCallbacks(timeoutRunnable)
        timeoutHandler.postDelayed(timeoutRunnable, NfcConstants.TRANSACTION_TIMEOUT_MS)
    }

    private fun handleTimeout() {
        nfcTransport.reset()
        router.resetAll()
        sendLogToGui("Session Timeout")
    }

    override fun onDeactivated(reason: Int) {
        timeoutHandler.removeCallbacks(timeoutRunnable)
        nfcTransport.reset()
    }
}
