package com.example.a100_basiccrypto

import android.app.DatePickerDialog
import android.app.TimePickerDialog
import android.content.Context
import android.os.Bundle
import android.text.InputType
import android.util.Log
import android.view.View
import android.view.inputmethod.InputMethodManager
import android.widget.CheckBox
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.lifecycle.lifecycleScope
import com.example.a100_basiccrypto.digitalkey.core.*
import com.example.a100_basiccrypto.digitalkey.crypto.DilithiumIdentityCryptoImpl
import com.example.a100_basiccrypto.digitalkey.storage.SecureKeyStorageManager
import com.google.android.material.tabs.TabLayout
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.*

class ShareConfigActivity : AppCompatActivity() {

    private val storageManager by lazy { SecureKeyStorageManager(this) }
    private val sharingManager by lazy { SharingManager(DilithiumIdentityCryptoImpl(), storageManager) }
    
    private lateinit var etRecipient: EditText
    private lateinit var etFriendlyName: EditText
    private lateinit var tlShareType: TabLayout
    private var ownerKeyId: ByteArray? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_share_config)

        ownerKeyId = intent.getByteArrayExtra("OWNER_KEY_ID")
        etRecipient = findViewById(R.id.et_share_recipient)
        etFriendlyName = findViewById(R.id.et_share_friendly_name)
        tlShareType = findViewById(R.id.tl_share_type)

        setupToolbar()
        setupTabs()
        setupDateTimePickers()
        setupSendButton()
    }

    private fun setupToolbar() {
        val toolbar = findViewById<Toolbar>(R.id.toolbar_share_config)
        setSupportActionBar(toolbar)
        toolbar.setNavigationOnClickListener { finish() }
    }

    private fun setupTabs() {
        val containerPermanent = findViewById<View>(R.id.container_permanent)
        val containerTimed = findViewById<View>(R.id.container_timed)
        val containerOneTime = findViewById<View>(R.id.container_one_time)
        val containerRecurring = findViewById<View>(R.id.container_recurring)

        tlShareType.addOnTabSelectedListener(object : TabLayout.OnTabSelectedListener {
            override fun onTabSelected(tab: TabLayout.Tab?) {
                containerPermanent.visibility = View.GONE
                containerTimed.visibility = View.GONE
                containerOneTime.visibility = View.GONE
                containerRecurring.visibility = View.GONE
                
                when (tab?.position) {
                    0 -> containerPermanent.visibility = View.VISIBLE
                    1 -> containerTimed.visibility = View.VISIBLE
                    2 -> containerOneTime.visibility = View.VISIBLE
                    3 -> containerRecurring.visibility = View.VISIBLE
                }
            }
            override fun onTabUnselected(tab: TabLayout.Tab?) {}
            override fun onTabReselected(tab: TabLayout.Tab?) {}
        })
    }

    private fun setupDateTimePickers() {
        val dateFields = listOf(
            R.id.et_timed_start, R.id.et_timed_end, R.id.et_onetime_window,
            R.id.et_recurring_from, R.id.et_recurring_to, R.id.et_recurring_window
        )
        
        dateFields.forEach { id ->
            findViewById<EditText>(id).apply {
                inputType = InputType.TYPE_NULL
                setOnClickListener { 
                    hideKeyboard(this)
                    when(id) {
                        R.id.et_timed_start, R.id.et_timed_end -> showDateTimePicker(this)
                        R.id.et_onetime_window, R.id.et_recurring_window -> showTimeRangePicker(this)
                        R.id.et_recurring_from, R.id.et_recurring_to -> showDatePicker(this)
                    }
                }
            }
        }
    }

    private fun hideKeyboard(view: View) {
        val imm = getSystemService(Context.INPUT_METHOD_SERVICE) as InputMethodManager
        imm.hideSoftInputFromWindow(view.windowToken, 0)
    }

    private fun showDateTimePicker(editText: EditText) {
        val calendar = Calendar.getInstance()
        DatePickerDialog(this, { _, year, month, day ->
            TimePickerDialog(this, { _, hour, minute ->
                val selected = String.format("%02d/%02d/%d %02d:%02d", day, month + 1, year, hour, minute)
                editText.setText(selected)
            }, calendar.get(Calendar.HOUR_OF_DAY), calendar.get(Calendar.MINUTE), true).show()
        }, calendar.get(Calendar.YEAR), calendar.get(Calendar.MONTH), calendar.get(Calendar.DAY_OF_MONTH)).show()
    }

    private fun showDatePicker(editText: EditText) {
        val calendar = Calendar.getInstance()
        DatePickerDialog(this, { _, year, month, day ->
            val selected = String.format("%02d/%02d/%d", day, month + 1, year)
            editText.setText(selected)
        }, calendar.get(Calendar.YEAR), calendar.get(Calendar.MONTH), calendar.get(Calendar.DAY_OF_MONTH)).show()
    }

    private fun showTimeRangePicker(editText: EditText) {
        val calendar = Calendar.getInstance()
        TimePickerDialog(this, { _, hour1, minute1 ->
            // Open second picker for end time
            TimePickerDialog(this, { _, hour2, minute2 ->
                val range = String.format("%02d:%02d - %02d:%02d", hour1, minute1, hour2, minute2)
                editText.setText(range)
            }, hour1 + 1, minute1, true).show()
        }, calendar.get(Calendar.HOUR_OF_DAY), calendar.get(Calendar.MINUTE), true).show()
    }

    private fun setupSendButton() {
        findViewById<View>(R.id.btn_send_ekey).setOnClickListener {
            val allKeys = storageManager.getAllKeys()
            val ownerRecord = if (ownerKeyId != null) {
                allKeys.find { it.keyID.contentEquals(ownerKeyId) }
            } else {
                allKeys.find { it.role == Role.OWNER }
            }

            if (ownerRecord == null) {
                Toast.makeText(this, "No Owner key found to share", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            
            val recipient = etRecipient.text.toString()
            if (recipient.isEmpty()) {
                Toast.makeText(this, "Please enter recipient info", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            performShare(ownerRecord, recipient)
        }
    }

    private fun performShare(ownerRecord: DigitalKeyRecord, recipient: String) {
        lifecycleScope.launch {
            try {
                var validityDays = 0
                var usageLimit = 0
                var daysOfWeek = 0
                var startM = -1
                var endM = -1

                when (tlShareType.selectedTabPosition) {
                    1 -> { // Timed
                        val startStr = findViewById<EditText>(R.id.et_timed_start).text.toString()
                        val endStr = findViewById<EditText>(R.id.et_timed_end).text.toString()
                        validityDays = calculateDaysBetween(startStr, endStr)
                    }
                    2 -> { // One-Time
                        usageLimit = 1
                        validityDays = 1 
                    }
                    3 -> { // Recurring
                        daysOfWeek = getSelectedDaysBitmask()
                        val timeRange = findViewById<EditText>(R.id.et_recurring_window).text.toString()
                        val (s, e) = parseTimeRange(timeRange)
                        startM = s
                        endM = e
                        validityDays = 30
                    }
                }

                val permissions = SharingConstants.PERM_UNLOCK or SharingConstants.PERM_LOCK or SharingConstants.PERM_START
                val friendlyName = etFriendlyName.text.toString().ifEmpty { "Key for $recipient" }

                val result = sharingManager.createInvitation(
                    ownerRecord, Role.FRIEND, permissions, validityDays,
                    usageLimit, daysOfWeek, startM, endM, friendlyName
                )

                if (result != null) {
                    Toast.makeText(this@ShareConfigActivity, 
                        "Invitation sent! Code: ${result.invitationCode}",
                        Toast.LENGTH_LONG).show()
                    finish()
                } else {
                    Toast.makeText(this@ShareConfigActivity, "Failed to create invitation", Toast.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                Log.e("ShareConfig", "Error: ${e.message}")
                Toast.makeText(this@ShareConfigActivity, "Error occurred", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun getSelectedDaysBitmask(): Int {
        var mask = 0
        if (findViewById<CheckBox>(R.id.cb_mon).isChecked) mask = mask or 2
        if (findViewById<CheckBox>(R.id.cb_tue).isChecked) mask = mask or 4
        if (findViewById<CheckBox>(R.id.cb_wed).isChecked) mask = mask or 8
        if (findViewById<CheckBox>(R.id.cb_thu).isChecked) mask = mask or 16
        if (findViewById<CheckBox>(R.id.cb_fri).isChecked) mask = mask or 32
        if (findViewById<CheckBox>(R.id.cb_sat).isChecked) mask = mask or 64
        if (findViewById<CheckBox>(R.id.cb_sun).isChecked) mask = mask or 1
        return mask
    }

    private fun parseTimeRange(range: String): Pair<Int, Int> {
        if (range.isEmpty()) return -1 to -1
        return try {
            val parts = range.split(" - ")
            val start = parts[0].split(":")
            val end = parts[1].split(":")
            val startM = start[0].toInt() * 60 + start[1].toInt()
            val endM = end[0].toInt() * 60 + end[1].toInt()
            startM to endM
        } catch (e: Exception) {
            -1 to -1
        }
    }

    private fun calculateDaysBetween(start: String, end: String): Int {
        return try {
            val sdf = SimpleDateFormat("dd/MM/yyyy HH:mm", Locale.getDefault())
            val d1 = sdf.parse(start)
            val d2 = sdf.parse(end)
            val diff = d2!!.time - d1!!.time
            (diff / (1000 * 60 * 60 * 24)).toInt().coerceAtLeast(1)
        } catch (e: Exception) { 1 }
    }
}
