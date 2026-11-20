package com.token2.fidoparole

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.core.app.ApplicationProvider
import com.github.takahirom.roborazzi.captureRoboImage
import com.token2.fidoparole.ui.App
import com.token2.fidoparole.ui.FidoParoleTheme
import com.token2.fidoparole.ui.FilePickers
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

/**
 * Renders the main screens on the JVM, with the real Rust core in demo mode.
 * Images go to app/build/screens (a review aid, not a pixel test).
 */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [35], qualifiers = "w393dp-h852dp-xxhdpi")
class ScreenshotTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    private fun checkAbout() {
        compose.onNodeWithContentDescription("More").performClick()
        compose.onNodeWithText("About / Info").performClick()
        compose.onNodeWithText("FidoParole Ordanexa").assertExists()
        compose.onNodeWithText("Version ${BuildConfig.VERSION_NAME}").assertExists()
        compose.onNodeWithText("Read-only by default").assertExists()
    }

    @Test
    fun mainScreens() {
        val vm = VaultViewModel(ApplicationProvider.getApplicationContext())
        compose.setContent { FidoParoleTheme { App(vm, FilePickers({ _, _ -> }, {})) } }
        compose.onRoot().captureRoboImage("build/screens/1-start.png")

        checkAbout()
        compose.onNodeWithText("Close").performClick()
        org.junit.Assert.assertFalse(vm.ui.value.editing)

        vm.editBiometricsAvailable = { true }
        vm.editGate = { true }
        vm.startDemo()
        try {
            compose.waitUntil(15_000) {
                org.robolectric.shadows.ShadowLooper.idleMainLooper()
                (vm.ui.value.status != null || vm.ui.value.error != null) && vm.ui.value.busy == null
            }
        } catch (e: Throwable) {
            throw AssertionError("state after wait: ${vm.ui.value}", e)
        }
        org.junit.Assert.assertNull("demo unlock failed", vm.ui.value.error)
        vm.clearMessage()
        compose.waitForIdle()
        compose.onRoot().captureRoboImage("build/screens/2-vault.png")
        checkAbout()
        compose.onNodeWithText("Close").performClick()
        org.junit.Assert.assertFalse(vm.ui.value.editing)

        vm.openEntry(vm.ui.value.entries.first { it.title == "GitHub" }.id)
        compose.waitForIdle()
        compose.onRoot().captureRoboImage("build/screens/3-entry.png")
        val entryBeforeAbout = vm.ui.value.entry
        checkAbout()
        compose.onNodeWithText("Close").performClick()
        org.junit.Assert.assertEquals(entryBeforeAbout, vm.ui.value.entry)
        org.junit.Assert.assertFalse(vm.ui.value.editing)

        compose.onNodeWithText("Generate password").assertDoesNotExist()
        vm.editGate = { throw TokenEditRequested() }
        compose.onNodeWithText("Edit").performClick()
        compose.waitUntil(5_000) { org.robolectric.shadows.ShadowLooper.idleMainLooper(); vm.ui.value.editTokenRequired }
        compose.onNodeWithText("Authenticate with your token").assertExists()
        compose.onNodeWithText("Token PIN").assertExists()
        compose.onNodeWithText("Cancel").performClick()
        org.junit.Assert.assertFalse(vm.ui.value.editing)
        compose.onNodeWithContentDescription("More").performClick()
        compose.onNodeWithText("Edit with token PIN").performClick()
        compose.onNodeWithText("Authenticate with your token").assertExists()
        compose.onNodeWithText("Cancel").performClick()
        org.junit.Assert.assertFalse(vm.ui.value.editing)
        vm.editGate = { true }
        compose.onNodeWithText("Edit").performClick()
        compose.waitUntil(5_000) { org.robolectric.shadows.ShadowLooper.idleMainLooper(); vm.ui.value.editing }
        compose.onNodeWithText("Generate password").assertExists()
        compose.onRoot().captureRoboImage("build/screens/3b-entry-edit.png")
        vm.update(uniffi.fidoparole_ffi.EntryField.NOTES, "Recovery codes are in the safe.")
        vm.closeEntry()
        compose.waitForIdle()
        compose.onRoot().captureRoboImage("build/screens/4-unsaved.png")
    }
}
