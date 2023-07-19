package tech.studi.toothbrushpasswordcalculator

import android.app.PendingIntent
import android.content.Intent
import android.content.IntentFilter
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.NfcA
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Button
import androidx.appcompat.app.AppCompatActivity
import android.widget.TextView
import java.io.IOException
import java.nio.ByteBuffer

class MainActivity : AppCompatActivity() {

    private var nfcAdapter: NfcAdapter? = null
    private var pendingIntent: PendingIntent? = null
    private var intentFiltersArray: Array<IntentFilter>? = null
    private lateinit var idTextView: TextView
    private lateinit var mfgDateView: TextView
    private lateinit var passwordView: TextView
    private lateinit var passwordDescription: TextView
    private lateinit var dateDescription: TextView
    private lateinit var idDescription: TextView
    private lateinit var resetButton: Button
    private lateinit var nfcA: NfcA

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        idTextView = findViewById(R.id.id_text)
        mfgDateView = findViewById(R.id.mfgDateView)
        passwordView = findViewById(R.id.passwordView)
        passwordDescription = findViewById(R.id.passwordDescription)
        idDescription = findViewById(R.id.idDescription)
        dateDescription = findViewById(R.id.dateDescription)
        resetButton = findViewById(R.id.resetButton)

        val intent = Intent(this, javaClass).apply {
            addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
        }
        pendingIntent = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE)

        intentFiltersArray = arrayOf(IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED))

        handleIntent(intent)
    }

    override fun onResume() {
        super.onResume()

        val intent = Intent(this, javaClass).apply {
            addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
        }
        val pendingIntent = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE)

        val techList = arrayOf(arrayOf(NfcA::class.java.name))

        nfcAdapter?.enableForegroundDispatch(this, pendingIntent, null, techList)
    }

    override fun onPause() {
        super.onPause()
        nfcAdapter?.disableForegroundDispatch(this)
        if (::nfcA.isInitialized) {
            try {
                nfcA.close()
            } catch (e: IOException) {
                e.printStackTrace()
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (NfcAdapter.ACTION_TECH_DISCOVERED == intent.action) {
            nfcA = NfcA.get(intent.getParcelableExtra(NfcAdapter.EXTRA_TAG))
            try {
                nfcA.connect()
            } catch (e: IOException) {
                e.printStackTrace()
            } catch (e: SecurityException) {
                e.printStackTrace()
            }

            // Pass the received intent to handleIntent() method
            handleIntent(intent)
        }
    }


    private fun handleIntent(intent: Intent) {
        when (intent.action) {
            NfcAdapter.ACTION_NDEF_DISCOVERED, NfcAdapter.ACTION_TECH_DISCOVERED -> {
                var idString: String = ""
                var mfgDate: String = ""
                // Fetch the NFC tag's ID.
                val tag = intent.getParcelableExtra<Tag>(NfcAdapter.EXTRA_TAG)
                val id = tag?.id
                if (id != null) {
                    // Convert the byte array ID to a hexadecimal string.
                    idString = id.joinToString("") { "%02x".format(it) }
                    idTextView.text = idString
                    idDescription.visibility = View.VISIBLE
                }
                if (!::nfcA.isInitialized) {
                    val tag = intent.getParcelableExtra<Tag>(NfcAdapter.EXTRA_TAG)
                    nfcA = NfcA.get(tag)
                    nfcA.connect()
                }

                val responseLow = nfcA.transceive(byteArrayOf(0x30, 0x21)).toHex()
                val responseHigh = nfcA.transceive(byteArrayOf(0x30, 0x22)).toHex()
                mfgDate = hexToString(responseLow, responseHigh)
                mfgDateView.text = mfgDate
                mfgDateView.visibility = View.VISIBLE
                dateDescription.visibility = View.VISIBLE
                val runtime = nfcA.transceive(byteArrayOf(0x30, 0x24)).toHex()
                Log.d("runtime", runtime)
                val idStringFixed = idString
                val mfgDateFixed = mfgDate
                if (!idStringFixed.isNullOrEmpty() && !mfgDateFixed.isNullOrEmpty()) {
                    val password =
                        getPassword(idStringFixed.toByteArray(), mfgDateFixed.toByteArray())
                    if (!password.isNullOrEmpty()) {
                        passwordView.text = password
                        passwordView.visibility = View.VISIBLE
                        passwordDescription.visibility = View.VISIBLE
                        resetButton.setOnClickListener { resetRuntime(password, runtime, nfcA) }
                        resetButton.visibility = View.VISIBLE
                    }
                }
            }
        }
    }

    private fun resetRuntime(password: String, runtime:String, nfcA: NfcA) {
        // Construct the AUTH command.
        val authCommand = byteArrayOf(0x1B) + password.hexStringToByteArray()

        // Transmit the AUTH command. This should return PACK if successful.
        val pack = nfcA.transceive(authCommand)

        // Convert the current value to a byte array
        val currentBytes = runtime.hexStringToByteArray()

        // Extract the bytes you want to keep from the current value
        // Assuming that these are the 3rd and 4th bytes in the array
        val keepByte1 = currentBytes[2]
        val keepByte2 = currentBytes[3]

        // Construct the WRITE command to overwrite the first two bytes
        val writeCommand = byteArrayOf(0xA2.toByte(), 0x24.toByte(), 0x00, 0x00, keepByte1, keepByte2)

        // Transmit the WRITE command. This does not return any data if successful.
        nfcA.transceive(writeCommand)
    }


    private fun ByteArray.toHex(): String {
        return joinToString(":") { "%02x".format(it) }
    }

    private fun crc16(crcInitial: Int, buffer: ByteArray, len: Int): Int {
        var crc = crcInitial
        var index = 0
        var lenMut = len
        while (lenMut-- > 0) {
            crc = crc xor (buffer[index++].toInt() shl 8)
            var bits = 0
            do {
                crc = if (crc and 0x8000 != 0) {
                    (2 * crc) xor 0x1021
                } else {
                    2 * crc
                }
            } while (++bits < 8)
        }
        return crc
    }

    private fun getPassword(nfctagUid: ByteArray, nfcTagHeadID: ByteArray): String {
        var crcCalc = crc16(0x49A3, nfctagUid, nfctagUid.size) // Calculate the NTAG UID CRC

        crcCalc =
            crcCalc or (crc16(
                crcCalc,
                nfcTagHeadID,
                nfcTagHeadID.size
            ) shl 16) // Calculate the MFG CRC

        val byteBuffer = ByteBuffer.allocate(4).putInt(crcCalc)
        val arr = byteBuffer.array()
        crcCalc =
            (arr[3].toInt() shl 24) or (arr[2].toInt() and 0xff shl 16) or (arr[1].toInt() and 0xff shl 8) or (arr[0].toInt() and 0xff)
        return crcCalc.toString(16).uppercase()
    }

    fun hexToString(lower: String, higher: String): String {
        // Prepend two octets from hex1 to hex2
        val combinedHex = lower.split(":").subList(2, 4) + higher.split(":")
        // Take first 10 octets
        val trimmedHex = combinedHex.take(10)
        // Convert octets to ASCII chars and join them into a single string
        return trimmedHex.map { it.toInt(16).toChar() }.joinToString("")
    }

    fun String.hexStringToByteArray(): ByteArray {
        val hexString = this.replace(":", "")
        val data = ByteArray(hexString.length / 2)
        for (i in data.indices) {
            val index = i * 2
            val j = hexString.substring(index, index + 2).toInt(16)
            data[i] = j.toByte()
        }
        return data
    }


}
