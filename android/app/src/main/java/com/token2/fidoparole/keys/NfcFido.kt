package com.token2.fidoparole.keys

import android.nfc.tech.IsoDep
import uniffi.fidoparole_ffi.FpException
import uniffi.fidoparole_ffi.NfcLink
import java.io.IOException

/** APDUs to a FIDO key held to the phone (ISO-DEP / ISO 14443-4). */
class IsoDepLink(private val iso: IsoDep) : NfcLink, AutoCloseable {
    init {
        try {
            if (!iso.isConnected) iso.connect()
        } catch (e: IOException) {
            throw FpException.Link("Could not talk to the key over NFC (${e.javaClass.simpleName}${e.message?.let { ": $it" } ?: ""}). Hold it flat against the back of the phone and try again.")
        }
        iso.timeout = 10_000 // the key may take a few seconds (PIN check, largeBlob write)
    }

    override fun transmit(apdu: ByteArray): ByteArray = try {
        iso.transceive(apdu)
    } catch (e: IOException) {
        throw FpException.Link("The key moved away from the phone (${e.javaClass.simpleName}). Hold it still until FidoParole says it's done.")
    }

    override fun close() {
        try { iso.close() } catch (_: IOException) {}
    }
}
