package com.token2.fidoparole

import android.app.Application
import android.net.Uri
import androidx.test.core.app.ApplicationProvider
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowLooper
import uniffi.fidoparole_ffi.EntryField
import uniffi.fidoparole_ffi.GenOptions

/** Exercise the normal ViewModel entry points against the real Rust demo vault. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class ReadOnlyTest {
    private lateinit var vm: VaultViewModel

    @Before fun openDemo() {
        vm = VaultViewModel(ApplicationProvider.getApplicationContext<Application>())
        vm.startDemo()
        await { vm.ui.value.status != null || vm.ui.value.error != null }
        assertNull(vm.ui.value.error)
        assertFalse(vm.ui.value.editing)
        vm.openEntry(vm.ui.value.entries.first().id)
    }

    @After fun close() { vm.lock(); vm.access.closeUsb() }

    private fun await(done: () -> Boolean) {
        val deadline = System.nanoTime() + 15_000_000_000L
        while (System.nanoTime() < deadline) {
            ShadowLooper.idleMainLooper()
            if (done() && vm.ui.value.busy == null) return
            Thread.sleep(10)
        }
        fail("Operation did not finish: ${vm.ui.value}")
    }

    @Test fun readOnlyRejectsEveryMutationWithoutChangingTheSession() {
        val original = vm.ui.value.entry!!
        val count = vm.ui.value.entries.size
        val mutations: List<() -> Unit> = listOf(
            { vm.addEntry() },
            { vm.update(EntryField.NOTES, "must not change") },
            { vm.generate(GenOptions(24u, true, true, true, true)) },
            { vm.deleteEntry() },
            { vm.save() },
            { vm.copyToOtherKey(null, "1234", "copy") },
            { vm.deleteVault() },
            { vm.importBackup(Uri.EMPTY, "dummy passphrase", false) },
            { vm.create("new vault", "1234", false) },
        )
        mutations.forEach { mutate ->
            vm.clearError()
            mutate()
            assertTrue(vm.ui.value.error.orEmpty().startsWith("Read-only mode."))
            assertNull(vm.ui.value.busy)
            assertFalse(vm.ui.value.status!!.dirty)
            assertEquals(count, vm.ui.value.entries.size)
            assertEquals(original, vm.ui.value.entry)
        }
        vm.clearError()
        vm.toggleReveal()
        assertNotNull(vm.ui.value.revealed)
        vm.copy(EntryField.PASSWORD)
        assertNull(vm.ui.value.error)
    }

    @Test fun explicitEditingCanSaveAndAutomaticallyReturnsToReadOnly() {
        vm.enableEditing()
        assertTrue(vm.ui.value.editing)
        val notes = vm.ui.value.entry!!.notes + "\nRead-only regression fixture"
        vm.update(EntryField.NOTES, notes)
        assertEquals(notes, vm.ui.value.entry!!.notes)
        assertTrue(vm.ui.value.status!!.dirty)
        vm.finishEditing()
        assertTrue(vm.ui.value.editing)
        assertNotNull(vm.ui.value.error)
        vm.clearError()
        vm.save()
        await { !vm.ui.value.editing || vm.ui.value.error != null }
        assertNull(vm.ui.value.error)
        assertFalse(vm.ui.value.editing)
        assertFalse(vm.ui.value.status!!.dirty)
        // A callback from an old edit screen must not change a saved vault.
        vm.update(EntryField.NOTES, "stale callback")
        assertEquals(notes, vm.ui.value.entry!!.notes)
        assertFalse(vm.ui.value.status!!.dirty)
    }

    @Test fun doneWithoutChangesAndLockBothRevokeEditing() {
        vm.enableEditing()
        vm.finishEditing()
        assertFalse(vm.ui.value.editing)
        vm.enableEditing()
        vm.lock()
        assertFalse(vm.ui.value.editing)
        assertNull(vm.ui.value.status)
        vm.startDemo()
        await { vm.ui.value.status != null || vm.ui.value.error != null }
        assertFalse(vm.ui.value.editing)
    }
}
