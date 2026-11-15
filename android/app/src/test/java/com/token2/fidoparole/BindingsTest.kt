package com.token2.fidoparole

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.fidoparole_ffi.EntryField
import uniffi.fidoparole_ffi.FpException
import uniffi.fidoparole_ffi.GenOptions
import uniffi.fidoparole_ffi.HidLink
import uniffi.fidoparole_ffi.KeyLink
import uniffi.fidoparole_ffi.KeyListener
import uniffi.fidoparole_ffi.NfcLink
import uniffi.fidoparole_ffi.demoPin
import uniffi.fidoparole_ffi.unlock

/** The generated Kotlin bindings against the real Rust library (host build), via JNA. */
class BindingsTest {
    @Test
    fun demoVaultRoundTrip() {
        var touches = 0
        val listener = object : KeyListener { override fun touchNeeded() { touches++ } }
        val link = KeyLink.demo(listener)
        assertTrue(link.info().problem == null)
        val v = unlock(link, demoPin()).single()
        assertEquals("Demo vault", v.status().name)
        val before = v.entries("").size
        val id = v.addEntry("JVM test")
        v.updateEntry(id, EntryField.USERNAME, "kotlin")
        v.generatePassword(id, GenOptions(24u, true, true, true, false))
        val pw = v.password(id)
        assertEquals(24, pw.length)
        assertTrue(v.status().dirty)
        val st = v.save(link)
        assertTrue(!st.dirty && st.pinSaved)
        assertTrue("touch callback from Rust reached Kotlin", touches > 0)

        val again = unlock(KeyLink.demo(null), demoPin()).single()
        assertEquals(before + 1, again.entries("").size)
        assertEquals("kotlin", again.entry(id).username)
        assertEquals(pw, again.password(id))
        again.lock()
        assertTrue(again.isLocked())
    }

    @Test
    fun wrongPinIsAKeyErrorWithItsCode() {
        val e = assertThrows(FpException.Key::class.java) { unlock(KeyLink.demo(null), "0000") }
        assertEquals(0x31.toUByte(), e.code)
        assertEquals("wrong PIN", e.detail)
        unlock(KeyLink.demo(null), demoPin()) // a correct PIN resets the counter
    }

    @Test
    fun kotlinLinkErrorsComeBackAsLinkErrors() {
        val unplugged = object : HidLink {
            override fun writeReport(report: ByteArray) { throw FpException.Link("unplugged") }
            override fun readReport(timeoutMs: UInt): ByteArray? = null
        }
        assertThrows(FpException.Link::class.java) { KeyLink.usb(unplugged, null) }
        val notFido = object : NfcLink { override fun transmit(apdu: ByteArray) = byteArrayOf(0x6A, 0x82.toByte()) }
        val e = assertThrows(FpException::class.java) { KeyLink.nfc(notFido, null) }
        assertTrue(e.message!!.contains("no FIDO applet"))
    }
}
