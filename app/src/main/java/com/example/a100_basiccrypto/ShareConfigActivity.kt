package com.example.a100_basiccrypto

import android.app.DatePickerDialog
import android.app.TimePickerDialog
import android.os.Bundle
import android.view.View
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import com.google.android.material.tabs.TabLayout
import java.util.*

class ShareConfigActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_share_config)

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
        val tlShareType = findViewById<TabLayout>(R.id.tl_share_type)
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
        // Timed Tab
        findViewById<EditText>(R.id.et_timed_start).setOnClickListener { showDateTimePicker(it as EditText) }
        findViewById<EditText>(R.id.et_timed_end).setOnClickListener { showDateTimePicker(it as EditText) }

        // One-Time Tab
        findViewById<EditText>(R.id.et_onetime_window).setOnClickListener { showTimeRangePicker(it as EditText) }

        // Recurring Tab
        findViewById<EditText>(R.id.et_recurring_from).setOnClickListener { showDatePicker(it as EditText) }
        findViewById<EditText>(R.id.et_recurring_to).setOnClickListener { showDatePicker(it as EditText) }
        findViewById<EditText>(R.id.et_recurring_window).setOnClickListener { showTimeRangePicker(it as EditText) }
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
            TimePickerDialog(this, { _, hour2, minute2 ->
                val range = String.format("%02d:%02d - %02d:%02d", hour1, minute1, hour2, minute2)
                editText.setText(range)
            }, hour1 + 1, minute1, true).show()
        }, calendar.get(Calendar.HOUR_OF_DAY), calendar.get(Calendar.MINUTE), true).show()
    }

    private fun setupSendButton() {
        findViewById<View>(R.id.btn_send_ekey).setOnClickListener {
            Toast.makeText(this, "Invitation sent successfully!", Toast.LENGTH_LONG).show()
            finish()
        }
    }
}
