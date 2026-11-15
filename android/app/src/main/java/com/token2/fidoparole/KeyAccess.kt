package com.token2.fidoparole

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbManager
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Build
import androidx.core.content.ContextCompat
import com.token2.fidoparole.keys.IsoDepLink
import com.token2.fidoparole.keys.UsbFido
import com.token2.fidoparole.keys.UsbHidLink
import com.token2.fidoparole.keys.UsbKey
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import uniffi.fidoparole_ffi.FpException
import uniffi.fidoparole_ffi.KeyLink
import uniffi.fidoparole_ffi.KeyListener

/** Where the key is: plugged in (USB) or held to the phone (NFC). */
sealed interface KeyChoice {
    data class Usb(val key: UsbKey) : KeyChoice
    data object Nfc : KeyChoice
    /** Built-in software key with a sample vault (no hardware). */
    data object Demo : KeyChoice
}

/**
 * Opens [KeyLink]s. USB links stay open while the key is plugged in; an NFC
 * link lives for one tap: the caller waits for a tag, runs its work while the
 * key is held to the phone, and the link is closed afterwards.
 */
class KeyAccess(private val ctx: Context) {
    private val usb = ctx.getSystemService(Context.USB_SERVICE) as UsbManager
    private var usbOpen: Triple<String, UsbHidLink, KeyLink>? = null
    private var demoLink: KeyLink? = null

    private val _nfcWanted = MutableStateFlow(false)
    /** The activity enables NFC reader mode while this is true. */
    val nfcWanted: StateFlow<Boolean> = _nfcWanted
    @Volatile private var pendingTag: CompletableDeferred<Tag>? = null

    fun usbKeys(): List<UsbKey> = UsbFido.find(usb)

    /** Called by the activity's NFC reader callback. */
    fun onTag(tag: Tag) {
        pendingTag?.complete(tag)
    }

    fun cancelNfc() {
        pendingTag?.cancel()
    }

    private suspend fun awaitTag(): Tag {
        val d = CompletableDeferred<Tag>()
        pendingTag = d
        _nfcWanted.value = true
        // Reader mode must stay on while the tag is used: turning it off
        // invalidates the Tag and IsoDep.connect() then fails with IOException.
        try { return d.await() } catch (e: Throwable) { _nfcWanted.value = false; throw e } finally { pendingTag = null }
    }

    private suspend fun ensurePermission(dev: UsbDevice): Boolean {
        if (usb.hasPermission(dev)) return true
        val result = CompletableDeferred<Boolean>()
        val action = ctx.packageName + ".USB_PERMISSION"
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(c: Context, i: Intent) {
                result.complete(i.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false))
            }
        }
        ContextCompat.registerReceiver(ctx, receiver, IntentFilter(action), ContextCompat.RECEIVER_NOT_EXPORTED)
        try {
            val flags = if (Build.VERSION.SDK_INT >= 31) PendingIntent.FLAG_MUTABLE else 0
            val pi = PendingIntent.getBroadcast(ctx, 0, Intent(action).setPackage(ctx.packageName), flags)
            usb.requestPermission(dev, pi)
            return result.await()
        } finally {
            ctx.unregisterReceiver(receiver)
        }
    }

    private suspend fun usbLink(key: UsbKey, listener: KeyListener): KeyLink {
        usbOpen?.let { (id, _, link) -> if (id == key.id) return link else closeUsb() }
        if (!ensurePermission(key.device)) throw FpException.Link("USB access to the key was not allowed")
        val conn = usb.openDevice(key.device) ?: throw FpException.Link("Could not open the USB key")
        if (!conn.claimInterface(key.iface, true)) { conn.close(); throw FpException.Link("The USB key is busy in another app") }
        if (!UsbFido.isFido(conn, key)) { conn.close(); throw FpException.Other("This USB device is not a FIDO security key") }
        val hid = UsbHidLink(conn, key)
        val link = try { KeyLink.usb(hid, listener) } catch (e: Exception) { hid.close(); throw e }
        usbOpen = Triple(key.id, hid, link)
        return link
    }

    fun closeUsb() {
        usbOpen?.let { (_, hid, link) -> link.close(); hid.close() }
        usbOpen = null
    }

    /** USB device unplugged: drop the open link if it was that one. */
    fun onUsbDetached(deviceName: String) {
        if (usbOpen?.first == deviceName) closeUsb()
    }

    /**
     * Run [block] with a link to the key. For NFC this suspends until a key is
     * held to the phone ([onWaitingForTag] tells the UI), then runs [block]
     * while it stays there.
     */
    suspend fun <T> withKey(choice: KeyChoice, listener: KeyListener, onWaitingForTag: () -> Unit = {}, onTagFound: () -> Unit = {}, block: (KeyLink) -> T): T =
        when (choice) {
            is KeyChoice.Usb -> {
                val link = usbLink(choice.key, listener)
                try { block(link) } catch (e: FpException.Link) { closeUsb(); throw e }
            }
            KeyChoice.Demo -> block(demoLink ?: KeyLink.demo(listener).also { demoLink = it })
            KeyChoice.Nfc -> {
                onWaitingForTag()
                val tag = awaitTag()
                try {
                    onTagFound()
                    val iso = IsoDep.get(tag) ?: throw FpException.Other("This NFC tag is not a FIDO security key")
                    IsoDepLink(iso).use { nfc ->
                        val link = KeyLink.nfc(nfc, listener)
                        try { block(link) } finally { link.close() }
                    }
                } finally {
                    _nfcWanted.value = false // reader mode off only after the key is done
                }
            }
        }
}
