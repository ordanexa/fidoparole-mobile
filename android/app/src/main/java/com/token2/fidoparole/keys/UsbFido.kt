package com.token2.fidoparole.keys

import android.hardware.usb.UsbConstants
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbDeviceConnection
import android.hardware.usb.UsbEndpoint
import android.hardware.usb.UsbInterface
import android.hardware.usb.UsbManager
import android.hardware.usb.UsbRequest
import java.nio.ByteBuffer
import java.util.concurrent.TimeoutException
import uniffi.fidoparole_ffi.FpException
import uniffi.fidoparole_ffi.HidLink

/** A FIDO HID interface on a USB device (security key over USB-C / OTG). */
data class UsbKey(val device: UsbDevice, val iface: UsbInterface, val epIn: UsbEndpoint, val epOut: UsbEndpoint) {
    val id: String get() = device.deviceName
    val label: String
        get() = listOfNotNull(device.manufacturerName, device.productName).joinToString(" ").ifBlank { "USB security key" }
    val serial: String? get() = try { device.serialNumber } catch (_: SecurityException) { null }
}

object UsbFido {
    /**
     * FIDO keys expose a HID interface with one interrupt IN and one interrupt
     * OUT endpoint of 64 bytes (keyboards and mice have no OUT endpoint). The
     * report descriptor (usage page 0xF1D0) is checked once the device is open.
     */
    fun find(usb: UsbManager): List<UsbKey> = usb.deviceList.values.flatMap { dev ->
        (0 until dev.interfaceCount).mapNotNull { i ->
            val itf = dev.getInterface(i)
            // FIDO HID: class 3, no boot subclass/protocol (keyboards and mice use those).
            if (itf.interfaceClass != UsbConstants.USB_CLASS_HID || itf.interfaceSubclass != 0 || itf.interfaceProtocol != 0) return@mapNotNull null
            var epIn: UsbEndpoint? = null
            var epOut: UsbEndpoint? = null
            for (e in 0 until itf.endpointCount) {
                val ep = itf.getEndpoint(e)
                if (ep.type != UsbConstants.USB_ENDPOINT_XFER_INT || ep.maxPacketSize != 64) continue
                if (ep.direction == UsbConstants.USB_DIR_IN) epIn = ep else epOut = ep
            }
            if (epIn != null && epOut != null) UsbKey(dev, itf, epIn, epOut) else null
        }
    }

    /** True if the interface's HID report descriptor declares the FIDO usage page. */
    fun isFido(conn: UsbDeviceConnection, key: UsbKey): Boolean {
        val buf = ByteArray(256)
        // GET_DESCRIPTOR (HID report descriptor 0x22) to the interface.
        val n = conn.controlTransfer(0x81, 0x06, 0x2200, key.iface.id, buf, buf.size, 1000)
        if (n <= 0) return true // can't tell; let the CTAPHID handshake decide
        for (i in 0 until n - 2) {
            if (buf[i] == 0x06.toByte() && buf[i + 1] == 0xD0.toByte() && buf[i + 2] == 0xF1.toByte()) return true
        }
        return false
    }
}

/**
 * 64-byte HID reports over the interface's interrupt endpoints.
 *
 * Reads use a queued [UsbRequest] that stays queued across timeouts, so a
 * report that arrives just as a wait times out is not lost (a timed-out
 * bulkTransfer can drop it on some phones). Writes are synchronous.
 */
class UsbHidLink(private val conn: UsbDeviceConnection, private val key: UsbKey) : HidLink, AutoCloseable {
    @Volatile private var closed = false
    private val lock = Any()
    private var inReq: UsbRequest? = null
    private val inBuf: ByteBuffer = ByteBuffer.allocateDirect(64)
    private var pending = false

    override fun writeReport(report: ByteArray) {
        if (closed) throw FpException.Link("The USB key was disconnected")
        val n = conn.bulkTransfer(key.epOut, report, report.size, 2000)
        if (n != report.size) throw FpException.Link("Writing to the USB key failed — is it still plugged in?")
    }

    override fun readReport(timeoutMs: UInt): ByteArray? = synchronized(lock) {
        if (closed) throw FpException.Link("The USB key was disconnected")
        val req = inReq ?: UsbRequest().also {
            if (!it.initialize(conn, key.epIn)) throw FpException.Link("Could not read from the USB key")
            inReq = it
        }
        if (!pending) {
            inBuf.clear()
            if (!req.queue(inBuf)) throw FpException.Link("Reading from the USB key failed — is it still plugged in?")
            pending = true
        }
        val done = try {
            conn.requestWait(timeoutMs.toLong().coerceIn(1, 5000))
        } catch (_: TimeoutException) {
            return null // still queued; the next call keeps waiting for it
        } ?: throw FpException.Link("The USB connection was interrupted — unplug the key and plug it in again")
        if (done !== req) return null
        pending = false
        val n = inBuf.position()
        if (n <= 0) return null
        val out = ByteArray(n)
        inBuf.flip(); inBuf.get(out)
        out
    }

    override fun close() {
        closed = true
        synchronized(lock) {
            inReq?.let { try { it.cancel() } catch (_: Exception) {}; try { it.close() } catch (_: Exception) {} }
            inReq = null; pending = false
        }
        try { conn.releaseInterface(key.iface) } catch (_: Exception) {}
        conn.close()
    }
}
