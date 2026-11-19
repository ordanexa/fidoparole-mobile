package com.token2.fidoparole

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import android.nfc.NfcAdapter
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.token2.fidoparole.ui.App
import com.token2.fidoparole.ui.FidoParoleTheme
import com.token2.fidoparole.ui.FilePickers
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.suspendCancellableCoroutine
import uniffi.fidoparole_ffi.FpException
import javax.crypto.Cipher
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

// FragmentActivity (a ComponentActivity) because BiometricPrompt needs one.
class MainActivity : FragmentActivity() {
    private val vm: VaultViewModel by viewModels()
    private var nfc: NfcAdapter? = null
    private var readerOn = false
    private var editPromptActive = false
    private var pendingExport: ((android.net.Uri) -> Unit)? = null
    private var pendingImport: ((android.net.Uri) -> Unit)? = null

    private val exportDoc = registerForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        uri?.let { pendingExport?.invoke(it) }; pendingExport = null
    }
    private val importDoc = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri?.let { pendingImport?.invoke(it) }; pendingImport = null
    }

    private val usbEvents = object : BroadcastReceiver() {
        override fun onReceive(c: Context, i: Intent) {
            when (i.action) {
                Intent.ACTION_SCREEN_OFF -> vm.onBackground()
                UsbManager.ACTION_USB_DEVICE_ATTACHED -> vm.refreshUsb()
                UsbManager.ACTION_USB_DEVICE_DETACHED -> {
                    val dev: UsbDevice? = if (Build.VERSION.SDK_INT >= 33) i.getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice::class.java)
                        else @Suppress("DEPRECATION") i.getParcelableExtra(UsbManager.EXTRA_DEVICE)
                    dev?.let { vm.onUsbDetached(it.deviceName) } ?: vm.refreshUsb()
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // No screenshots, no previews in the app switcher: passwords are on screen.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        enableEdgeToEdge()
        vm.gate = ::biometric
        vm.editGate = ::authenticateEdit
        nfc = NfcAdapter.getDefaultAdapter(this)
        vm.setNfcAvailable(nfc?.isEnabled == true)
        ContextCompat.registerReceiver(this, usbEvents, IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_OFF)
            addAction(UsbManager.ACTION_USB_DEVICE_ATTACHED); addAction(UsbManager.ACTION_USB_DEVICE_DETACHED)
        }, ContextCompat.RECEIVER_EXPORTED)

        // NFC reader mode only while an operation waits for a key.
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.RESUMED) {
                vm.access.nfcWanted.collect { wanted -> setReader(wanted) }
            }
        }

        val files = FilePickers(
            exportTo = { name, cb -> pendingExport = cb; exportDoc.launch(name) },
            importFrom = { cb -> pendingImport = cb; importDoc.launch(arrayOf("*/*")) },
        )
        setContent { FidoParoleTheme { App(vm, files) } }
    }

    /** Fingerprint / face / screen-lock prompt that unlocks a Keystore cipher. */
    private suspend fun biometric(title: String, subtitle: String, cipher: Cipher): Cipher = suspendCancellableCoroutine { cont ->
        val prompt = BiometricPrompt(this, ContextCompat.getMainExecutor(this), object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                val c = result.cryptoObject?.cipher
                if (c != null) cont.resume(c) else cont.resumeWithException(FpException.Other("The phone did not unlock the saved PIN"))
            }
            override fun onAuthenticationError(code: Int, msg: CharSequence) {
                val cancelled = code == BiometricPrompt.ERROR_USER_CANCELED || code == BiometricPrompt.ERROR_NEGATIVE_BUTTON || code == BiometricPrompt.ERROR_CANCELED
                cont.resumeWithException(if (cancelled) PromptCancelled() else FpException.Other(msg.toString()))
            }
            // onAuthenticationFailed: a finger that didn't match; the prompt stays open.
        })
        val info = BiometricPrompt.PromptInfo.Builder().setTitle(title).setSubtitle(subtitle)
            .setAllowedAuthenticators(vm.pinAuthenticators())
            .apply { if (Build.VERSION.SDK_INT < 30) setNegativeButtonText("Cancel") }
            .setConfirmationRequired(false)
            .build()
        prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
        cont.invokeOnCancellation { prompt.cancelAuthentication() }
    }

    /** Every Edit request opens a new system prompt; never reuse the unlock result. */
    private suspend fun authenticateEdit(): Boolean {
        editPromptActive = true
        try {
            val approved = awaitEditAuthentication()
            // Device-credential confirmation can stop this activity. Wait for its return.
            lifecycle.currentStateFlow.first { it.isAtLeast(Lifecycle.State.RESUMED) }
            return approved
        } finally {
            editPromptActive = false
        }
    }

    private suspend fun awaitEditAuthentication(): Boolean = suspendCancellableCoroutine { cont ->
        val authenticators = if (Build.VERSION.SDK_INT >= 30)
            androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG or
                androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
        else androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
        if (androidx.biometric.BiometricManager.from(this).canAuthenticate(authenticators) !=
            androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS) {
            cont.resumeWithException(FpException.Other("Set up a fingerprint or supported screen lock to enable editing."))
            return@suspendCancellableCoroutine
        }
        val prompt = BiometricPrompt(this, ContextCompat.getMainExecutor(this), object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                if (cont.isActive) cont.resume(true)
            }
            override fun onAuthenticationError(code: Int, msg: CharSequence) {
                if (!cont.isActive) return
                val cancelled = code == BiometricPrompt.ERROR_USER_CANCELED || code == BiometricPrompt.ERROR_NEGATIVE_BUTTON || code == BiometricPrompt.ERROR_CANCELED
                if (cancelled) cont.resume(false) else cont.resumeWithException(FpException.Other(msg.toString()))
            }
        })
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Authenticate to edit")
            .setSubtitle("Confirm your identity to allow changes to the vault")
            .setAllowedAuthenticators(authenticators)
            .apply { if (Build.VERSION.SDK_INT < 30) setNegativeButtonText("Cancel") }
            .build()
        cont.invokeOnCancellation { prompt.cancelAuthentication() }
        prompt.authenticate(info)
    }

    private fun setReader(on: Boolean) {
        val adapter = nfc ?: return
        if (on == readerOn) return
        readerOn = on
        if (on) {
            val flags = NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK
            adapter.enableReaderMode(this, { tag -> vm.access.onTag(tag) }, flags, Bundle().apply {
                putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 2000) // fewer presence checks while we talk to the key
            })
        } else {
            adapter.disableReaderMode(this)
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (intent.action == UsbManager.ACTION_USB_DEVICE_ATTACHED) vm.refreshUsb()
    }

    override fun onStart() { super.onStart(); vm.setNfcAvailable(nfc?.isEnabled == true); vm.onForeground(); vm.refreshUsb(); vm.refreshPinState() }
    override fun onUserLeaveHint() { super.onUserLeaveHint(); vm.onBackground() }
    override fun onStop() { super.onStop(); vm.onBackground(preserveEditPrompt = editPromptActive && !isFinishing) }
    override fun onPause() { super.onPause(); readerOn = false; nfc?.disableReaderMode(this) }

    override fun onDestroy() {
        unregisterReceiver(usbEvents)
        vm.gate = null
        vm.editGate = null
        super.onDestroy()
    }
}
