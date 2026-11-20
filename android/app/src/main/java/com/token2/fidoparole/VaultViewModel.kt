package com.token2.fidoparole

import android.app.Application
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.os.SystemClock
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.fidoparole_ffi.EntryDetails
import uniffi.fidoparole_ffi.EntryField
import uniffi.fidoparole_ffi.EntrySummary
import uniffi.fidoparole_ffi.FpException
import uniffi.fidoparole_ffi.GenOptions
import uniffi.fidoparole_ffi.KeyInfo
import uniffi.fidoparole_ffi.KeyLink
import uniffi.fidoparole_ffi.KeyListener
import uniffi.fidoparole_ffi.VaultSession
import uniffi.fidoparole_ffi.VaultStatus
import uniffi.fidoparole_ffi.createVault
import uniffi.fidoparole_ffi.demoPin
import uniffi.fidoparole_ffi.unlock as unlockKey

/** What the overlay shows while the key works. */
data class Busy(val text: String, val waitingForTag: Boolean = false, val touch: Boolean = false, val nfc: Boolean = false)

/** Shows the phone's fingerprint / screen-lock prompt for a Keystore cipher (provided by the activity). */
typealias BiometricGate = suspend (title: String, subtitle: String, cipher: javax.crypto.Cipher) -> javax.crypto.Cipher

data class UiState(
    /** Explicit write permission for this UI session; every opened vault starts read-only. */
    val editing: Boolean = false,
    val editAuthenticating: Boolean = false,
    val editTokenRequired: Boolean = false,
    val usbKeys: List<com.token2.fidoparole.keys.UsbKey> = emptyList(),
    /** null = NFC, otherwise the chosen USB key's id. */
    val usbChoice: String? = null,
    val keyInfo: KeyInfo? = null,
    val busy: Busy? = null,
    val message: String? = null,
    val error: String? = null,
    val choices: List<Pair<String, VaultSession>>? = null,
    val status: VaultStatus? = null,
    val entries: List<EntrySummary> = emptyList(),
    val query: String = "",
    val entry: EntryDetails? = null,
    val revealed: String? = null,
    val nfcAvailable: Boolean = true,
    /** A PIN is saved on this phone (behind fingerprint / screen lock). */
    val savedPin: Boolean = false,
    /** The phone has a fingerprint or screen lock, so a PIN can be saved. */
    val canSavePin: Boolean = false,
    /** PIN fields use the full keyboard (letters) instead of the number pad. */
    val pinAlpha: Boolean = false,
)

fun Throwable.userText(): String = when (this) {
    is FpException.Key -> detail
    is FpException.Link -> detail
    is FpException.Other -> detail
    else -> message?.takeIf { it.isNotBlank() }?.let { "$it (${javaClass.simpleName})" } ?: "Unexpected error: ${javaClass.simpleName}"
}

class VaultViewModel(app: Application) : AndroidViewModel(app) {
    val access = KeyAccess(app)
    private val pins = PinStore(app)
    private val prefs = app.getSharedPreferences("ui", Context.MODE_PRIVATE)
    /** Set by the activity while it is alive. */
    var gate: BiometricGate? = null
    /** A fresh system authentication, independent of whether a token PIN was saved. */
    var editGate: (suspend () -> Boolean)? = null
    var editBiometricsAvailable: (() -> Boolean)? = null
    private var editEpoch = 0L
    private var editJob: Job? = null
    private val _ui = MutableStateFlow(UiState())
    val ui: StateFlow<UiState> = _ui

    private var session: VaultSession? = null
    /** How the open vault's key is reached (same as at unlock). */
    private var sessionKey: KeyChoice = KeyChoice.Nfc
    private var job: Job? = null
    private var backgroundSince = 0L
    /** The user was warned about few PIN attempts left and tapped Unlock again. */
    @Volatile private var lowRetriesConfirmed = false
    private val clipHandler = Handler(Looper.getMainLooper())

    private val listener = object : KeyListener {
        override fun touchNeeded() { _ui.update { s -> s.copy(busy = s.busy?.takeIf { !it.nfc }?.copy(touch = true) ?: s.busy) } }
    }

    init {
        refreshUsb()
        _ui.update { it.copy(pinAlpha = prefs.getBoolean("pin_alpha", false)) }
        refreshPinState()
    }

    fun pinAuthenticators(): Int = pins.authenticators

    fun refreshPinState() = _ui.update { it.copy(savedPin = pins.has(), canSavePin = pins.available()) }

    fun setPinAlpha(alpha: Boolean) {
        prefs.edit().putBoolean("pin_alpha", alpha).apply()
        _ui.update { it.copy(pinAlpha = alpha) }
    }

    fun forgetSavedPin() {
        pins.forget(); refreshPinState()
        _ui.update { it.copy(message = "The saved PIN was removed from this phone") }
    }

    fun setNfcAvailable(available: Boolean) = _ui.update { it.copy(nfcAvailable = available) }

    fun enableEditing() {
        if (_ui.value.editing || _ui.value.editAuthenticating || _ui.value.busy != null || job?.isActive == true) return
        if (editBiometricsAvailable?.invoke() != true) {
            _ui.update { it.copy(editTokenRequired = true, error = null) }
            return
        }
        val authenticate = editGate ?: run {
            _ui.update { it.copy(error = "Device authentication is unavailable. Editing remains locked.") }
            return
        }
        val epoch = editEpoch
        val vault = session
        _ui.update { it.copy(editAuthenticating = true, error = null) }
        editJob = viewModelScope.launch {
            try {
                val approved = authenticate()
                if (approved && epoch == editEpoch && session === vault && _ui.value.busy == null) {
                    _ui.update { it.copy(editing = true) }
                }
            } catch (_: PromptCancelled) {
                // Cancellation leaves the vault read-only.
            } catch (e: CancellationException) {
                throw e
            } catch (e: Throwable) {
                if (epoch == editEpoch) _ui.update { it.copy(error = e.userText()) }
            } finally {
                if (epoch == editEpoch) _ui.update { it.copy(editAuthenticating = false) }
            }
        }
    }

    private fun revokeEditing() {
        editEpoch++
        editJob?.cancel()
        editJob = null
        _ui.update { it.copy(editing = false, editAuthenticating = false, editTokenRequired = false) }
    }

    fun cancelEditAuthentication() { revokeEditing() }

    /** Fresh PIN/UV verification on the actual vault's key, without modifying the vault. */
    fun authenticateEditWithToken(pin: String, fingerprint: Boolean = false) {
        if (!_ui.value.editTokenRequired || _ui.value.busy != null || job?.isActive == true) return
        val choice = if (sessionKey == KeyChoice.Demo && session != null) KeyChoice.Demo else currentChoice()
        if (fingerprint && choice is KeyChoice.Nfc) {
            _ui.update { it.copy(error = "Use the token PIN over NFC.") }; return
        }
        val credential = if (fingerprint) null else pin.ifEmpty {
            _ui.update { it.copy(error = "Enter the token PIN") }; return
        }
        val vault = session
        val epoch = editEpoch
        _ui.update { it.copy(editTokenRequired = false, editAuthenticating = true) }
        op("Authenticate on your security key — touch it when it blinks.", choice,
            nfcText = "Verifying your token — keep holding it against the phone…",
            after = {
                if (epoch == editEpoch && session === vault) _ui.update { it.copy(editing = true) }
            }) { link ->
            try {
                if (epoch != editEpoch || session !== vault) throw PromptCancelled()
                if (credential != null) {
                    val left = link!!.info().pinRetries
                    if (left in 1..2 && !lowRetriesConfirmed) {
                        lowRetriesConfirmed = true
                        throw FpException.Other("Only $left token PIN attempts left. Check the PIN and choose Edit again to retry.")
                    }
                }
                lowRetriesConfirmed = false
                if (vault != null) vault.authenticateEdit(link!!, credential)
                else link!!.verifyUser(credential)
            } finally {
                if (epoch == editEpoch) _ui.update { it.copy(editAuthenticating = false) }
            }
        }
    }

    fun finishEditing() {
        if (_ui.value.busy != null || job?.isActive == true) return
        if (_ui.value.status?.dirty == true) {
            _ui.update { it.copy(error = "Save your changes, or lock the vault to discard them, before returning to read-only mode.") }
            return
        }
        revokeEditing()
    }

    private fun writeAccess(): Boolean {
        if (_ui.value.editing) return true
        _ui.update { it.copy(error = "Read-only mode. Choose Edit before changing the vault or writing to a key.") }
        return false
    }

    private inline fun edit(block: () -> Unit) {
        if (writeAccess()) guard(block)
    }

    // ------------------------------------------------------------- keys ----

    fun refreshUsb() {
        val keys = access.usbKeys()
        _ui.update { s ->
            val choice = s.usbChoice?.takeIf { id -> keys.any { it.id == id } } ?: keys.firstOrNull()?.id
            s.copy(usbKeys = keys, usbChoice = choice, keyInfo = if (choice != s.usbChoice) null else s.keyInfo)
        }
    }

    fun onUsbDetached(name: String) { revokeEditing(); access.onUsbDetached(name); refreshUsb() }

    fun chooseUsb(id: String?) = _ui.update { it.copy(usbChoice = id, keyInfo = null) }

    private fun currentChoice(): KeyChoice {
        val s = _ui.value
        val key = s.usbKeys.firstOrNull { it.id == s.usbChoice }
        return if (key != null) KeyChoice.Usb(key) else KeyChoice.Nfc
    }

    /**
     * Run a key operation off the main thread with the busy overlay; errors
     * end up in `error`.
     */
    /**
     * [text] is shown for USB (where the key blinks and wants a touch);
     * [nfcText] once an NFC key is found (no touch: holding it is enough).
     * [after] runs on the main thread after success, with the overlay gone.
     */
    private fun op(text: String, choice: KeyChoice?, nfcText: String = "Working with the key — keep holding it against the phone…",
                   after: (suspend () -> Unit)? = null, block: suspend (KeyLink?) -> Unit) {
        if (job?.isActive == true) return
        job = viewModelScope.launch {
            val nfc = choice is KeyChoice.Nfc
            _ui.update { it.copy(busy = Busy(if (nfc) "Hold your key to the back of the phone" else text, waitingForTag = nfc, nfc = nfc), error = null) }
            var ok = false
            try {
                withContext(Dispatchers.IO) {
                    if (choice == null) block(null)
                    else access.withKey(choice, listener,
                        onWaitingForTag = { _ui.update { it.copy(busy = Busy("Hold your key to the back of the phone", waitingForTag = true, nfc = true)) } },
                        onTagFound = { _ui.update { it.copy(busy = Busy(nfcText, nfc = true)) } },
                    ) { link -> kotlinx.coroutines.runBlocking { block(link) } }
                }
                ok = true
            } catch (e: CancellationException) {
                // cancelled from the overlay
            } catch (e: Throwable) {
                _ui.update { it.copy(error = e.userText().replaceFirstChar { c -> c.uppercase() }) }
            } finally {
                _ui.update { it.copy(busy = null) }
            }
            if (ok && after != null) {
                try { after() } catch (e: CancellationException) { throw e } catch (e: Throwable) {
                    _ui.update { it.copy(error = e.userText().replaceFirstChar { c -> c.uppercase() }) }
                }
            }
        }
    }

    fun cancelBusy() { access.cancelNfc(); job?.cancel() }

    fun readKeyInfo() {
        val c = currentChoice()
        if (c !is KeyChoice.Usb) return
        op("Reading the key…", c, nfcText = "Reading the key…") { link -> _ui.update { it.copy(keyInfo = link!!.info()) } }
    }

    // ------------------------------------------------------ unlock/create --

    /**
     * Unlock with a typed PIN or the key's fingerprint. With [remember], the
     * PIN is saved on this phone afterwards (behind fingerprint / screen lock).
     */
    fun unlock(pin: String, fingerprint: Boolean, remember: Boolean = false, fromSaved: Boolean = false) {
        val choice = currentChoice()
        if (fingerprint && choice is KeyChoice.Nfc) { _ui.update { it.copy(error = "Over NFC the key has no power for its fingerprint sensor — use the PIN.") }; return }
        val p = if (fingerprint) null else pin.ifEmpty { _ui.update { it.copy(error = "Enter the key's PIN") }; return }
        val save = if (remember && p != null && !fromSaved) p else null
        op(if (fingerprint) "Touch the fingerprint sensor when the key blinks." else "Touch your key when it blinks.", choice,
            nfcText = "Reading your vault — keep holding the key against the phone…",
            after = save?.let { pinToSave -> suspend { savePin(pinToSave) } }) { link ->
            if (p != null) {
                // A wrong PIN costs a real attempt; with few left, ask for a second tap first.
                val left = link!!.info().pinRetries
                if (left in 1..2 && !lowRetriesConfirmed) {
                    lowRetriesConfirmed = true
                    throw FpException.Other("Only $left PIN attempt${if (left == 1) "" else "s"} left — a wrong PIN now could block the key. Check the PIN, then tap Unlock again to try anyway.")
                }
            }
            lowRetriesConfirmed = false
            val vaults = try { unlockKey(link!!, p) } catch (e: FpException.Key) {
                if (fromSaved && (e.code.toInt() == 0x31 || e.code.toInt() == 0x32)) {
                    // Never spend more attempts with a saved PIN that the key rejects.
                    pins.forget(); refreshPinState()
                    throw FpException.Other("The key rejected the saved PIN, so it was removed from this phone. Enter the PIN by hand.")
                }
                throw e
            }
            sessionKey = choice
            if (vaults.size == 1) open(vaults[0]) else _ui.update { it.copy(choices = vaults.map { v -> v.status().name.ifEmpty { "Vault" } to v }) }
        }
    }

    /** Unlock with the PIN saved on this phone: fingerprint / screen lock first. */
    fun unlockWithSavedPin() {
        val g = gate ?: return
        if (job?.isActive == true) return
        viewModelScope.launch {
            val cipher = pins.decryptCipher() ?: run {
                refreshPinState()
                _ui.update { it.copy(error = "The saved PIN is no longer usable (the phone's fingerprints or screen lock changed). Enter the PIN and save it again.") }
                return@launch
            }
            val pin = try { pins.read(g("Unlock FidoParole", "Use the PIN saved on this phone", cipher)) }
                catch (e: CancellationException) { throw e }
                catch (e: Throwable) { e.message?.takeIf { it.isNotBlank() && e !is PromptCancelled }?.let { m -> _ui.update { it.copy(error = m) } }; return@launch }
            unlock(pin, fingerprint = false, fromSaved = true)
        }
    }

    private suspend fun savePin(pin: String) {
        val g = gate ?: return
        if (!pins.available()) return
        try {
            pins.store(g("Save the PIN on this phone", "Next time, unlock with your fingerprint or screen lock", pins.encryptCipher()), pin)
            refreshPinState()
            _ui.update { it.copy(message = "PIN saved on this phone") }
        } catch (e: PromptCancelled) {
            pins.forget(); refreshPinState()
        }
    }

    /** Open the sample vault on the built-in demo key (no hardware needed). */
    fun startDemo() {
        op("Opening the demo vault…", KeyChoice.Demo) { link ->
            val vaults = unlockKey(link!!, demoPin())
            sessionKey = KeyChoice.Demo
            open(vaults[0])
            _ui.update { it.copy(message = "Demo mode: a software key inside the app. Nothing is stored anywhere.") }
        }
    }

    fun choose(index: Int) {
        val c = _ui.value.choices ?: return
        c.forEachIndexed { i, (_, v) -> if (i != index) v.lock() }
        open(c[index].second)
    }

    fun cancelChoose() { _ui.value.choices?.forEach { it.second.lock() }; _ui.update { it.copy(choices = null) } }

    fun create(name: String, pin: String, fingerprint: Boolean) {
        if (!writeAccess()) return
        val choice = currentChoice()
        if (name.isBlank()) { _ui.update { it.copy(error = "Give the vault a name") }; return }
        val p = if (fingerprint) null else pin.ifEmpty { _ui.update { it.copy(error = "Enter the key's PIN") }; return }
        op("Creating the vault — touch your key each time it blinks (twice).", choice,
            nfcText = "Creating the vault — keep holding the key against the phone…") { link ->
            if (!writeAccess()) return@op
            val v = createVault(link!!, p, name.trim())
            sessionKey = choice
            open(v)
            _ui.update { it.copy(message = "Vault created on the key") }
        }
    }

    private fun open(v: VaultSession) {
        session = v
        val st = v.status()
        _ui.update { it.copy(editing = false, choices = null, status = st, entries = v.entries(""), query = "", entry = null, revealed = null,
            message = st.notice ?: st.problem) }
    }

    // ------------------------------------------------------------ entries --

    private fun refresh() {
        val v = session ?: return
        _ui.update { it.copy(status = v.status(), entries = v.entries(it.query)) }
    }

    fun search(q: String) { _ui.update { it.copy(query = q) }; refresh() }

    fun openEntry(id: String) = guard { _ui.update { it.copy(entry = session!!.entry(id), revealed = null) } }

    fun closeEntry() { _ui.update { it.copy(entry = null, revealed = null) }; refresh() }

    fun addEntry() = edit {
        val id = session!!.addEntry("New entry")
        refresh()
        openEntry(id)
    }

    fun update(field: EntryField, value: String) = edit {
        val v = session!!
        val id = _ui.value.entry?.id ?: return@edit
        v.updateEntry(id, field, value)
        _ui.update { it.copy(entry = v.entry(id), status = v.status(), revealed = if (field == EntryField.PASSWORD) value else it.revealed) }
    }

    fun deleteEntry() = edit {
        val id = _ui.value.entry?.id ?: return@edit
        session!!.deleteEntry(id)
        closeEntry()
    }

    fun toggleReveal() = guard {
        val e = _ui.value.entry ?: return@guard
        _ui.update { it.copy(revealed = if (it.revealed == null) session!!.password(e.id) else null) }
    }

    fun generate(opts: GenOptions) = edit {
        val id = _ui.value.entry?.id ?: return@edit
        session!!.generatePassword(id, opts)
        _ui.update { it.copy(entry = session!!.entry(id), revealed = session!!.password(id), status = session!!.status(), message = "New password generated") }
    }

    fun copy(field: EntryField) = guard {
        val e = _ui.value.entry ?: return@guard
        val text = when (field) {
            EntryField.PASSWORD -> session!!.password(e.id)
            EntryField.USERNAME -> e.username
            EntryField.URL -> e.url
            else -> return@guard
        }
        if (text.isEmpty()) return@guard
        copyToClipboard(text, sensitive = field == EntryField.PASSWORD)
        _ui.update { it.copy(message = "Copied — the clipboard clears in 30 s") }
    }

    private fun copyToClipboard(text: String, sensitive: Boolean) {
        val cm = getApplication<Application>().getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText("FidoParole", text)
        if (sensitive) {
            // Hidden from the clipboard preview and keyboard suggestions (Android 13+).
            clip.description.extras = PersistableBundle().apply { putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true) }
        }
        cm.setPrimaryClip(clip)
        clipHandler.removeCallbacksAndMessages(null)
        clipHandler.postDelayed({
            if (Build.VERSION.SDK_INT >= 28) cm.clearPrimaryClip() else cm.setPrimaryClip(ClipData.newPlainText("", ""))
        }, 30_000)
    }

    private inline fun guard(block: () -> Unit) {
        try { block() } catch (e: Throwable) { _ui.update { it.copy(error = e.userText()) } }
    }

    // ---------------------------------------------------------- key writes --

    fun save() {
        if (!writeAccess()) return
        val v = session ?: return
        val choice = keyForSessionOps()
        op(if (_ui.value.status?.pinSaved == false) "Saving — touch the fingerprint sensor when the key blinks." else "Saving to the key…", choice,
            nfcText = "Saving to the key — keep holding it against the phone…") { link ->
            if (!writeAccess() || session !== v) return@op
            // Over NFC each tap may be a different key: make sure it's this vault's key and unchanged.
            if (choice is KeyChoice.Nfc && v.reconnect(link!!)) {
                _ui.update { it.copy(error = "The vault on this key changed since you opened it (saved from another device). Lock and unlock again to see it, or save once more to overwrite it.") }
                refresh()
                return@op
            }
            if (!writeAccess() || session !== v) return@op
            v.save(link!!)
            refresh()
            _ui.update { it.copy(editing = false, message = "Saved to the key") }
        }
    }

    private fun keyForSessionOps(): KeyChoice {
        if (sessionKey == KeyChoice.Demo) return KeyChoice.Demo
        val usbNow = (sessionKey as? KeyChoice.Usb)?.let { k -> _ui.value.usbKeys.firstOrNull { it.id == k.key.id } }
        return if (usbNow != null) KeyChoice.Usb(usbNow) else KeyChoice.Nfc
    }

    fun copyToOtherKey(useUsb: com.token2.fidoparole.keys.UsbKey?, pin: String, name: String) {
        if (!writeAccess()) return
        val v = session ?: return
        if (pin.isEmpty()) { _ui.update { it.copy(error = "Enter the target key's PIN") }; return }
        val choice = if (useUsb != null) KeyChoice.Usb(useUsb) else KeyChoice.Nfc
        op("Copying — the target key blinks twice; touch it each time.", choice,
            nfcText = "Copying to this key — keep holding it against the phone…") { link ->
            if (!writeAccess() || session !== v) return@op
            v.copyToKey(link!!, pin, name.trim())
            _ui.update { it.copy(message = "The vault is now also on that key. The copies are independent.") }
        }
    }

    fun deleteVault() {
        if (!writeAccess()) return
        val v = session ?: return
        op("Removing the vault from the key…", keyForSessionOps(), nfcText = "Removing the vault — keep holding the key against the phone…") { link ->
            if (!writeAccess() || session !== v) return@op
            v.deleteFromKey(link!!)
            session = null
            _ui.update { it.copy(editing = false, status = null, entries = emptyList(), entry = null, revealed = null, message = "Vault deleted from the key") }
        }
    }

    fun exportBackup(uri: Uri, passphrase: String) {
        val v = session ?: return
        op("Encrypting the backup…", null) {
            val bytes = v.exportBackup(passphrase)
            getApplication<Application>().contentResolver.openOutputStream(uri)?.use { it.write(bytes) }
                ?: throw FpException.Other("Could not write the backup file")
            _ui.update { it.copy(message = "Backup saved") }
        }
    }

    fun importBackup(uri: Uri, passphrase: String, replace: Boolean) {
        if (!writeAccess()) return
        val v = session ?: return
        op("Decrypting the backup…", null) {
            val bytes = getApplication<Application>().contentResolver.openInputStream(uri)?.use { it.readBytes() }
                ?: throw FpException.Other("Could not read the backup file")
            if (!writeAccess() || session !== v) return@op
            val msg = v.importBackup(bytes, passphrase, replace)
            refresh()
            _ui.update { it.copy(message = "$msg Save to the key to keep it.") }
        }
    }

    // ----------------------------------------------------------- locking --

    fun lock() {
        revokeEditing()
        session?.lock()
        session = null
        clipHandler.removeCallbacksAndMessages(null)
        _ui.update { it.copy(editing = false, status = null, entries = emptyList(), entry = null, revealed = null, choices = null, query = "") }
    }

    fun onBackground() { revokeEditing(); backgroundSince = SystemClock.elapsedRealtime() }

    /** Auto-lock: 2 minutes in the background, 8 with unsaved changes. */
    fun onForeground() {
        if (backgroundSince == 0L || session == null) return
        val away = SystemClock.elapsedRealtime() - backgroundSince
        val limit = if (_ui.value.status?.dirty == true) 8 * 60_000L else 2 * 60_000L
        if (away > limit) {
            val dirty = _ui.value.status?.dirty == true
            lock()
            _ui.update { it.copy(message = if (dirty) "Locked after inactivity — unsaved changes were discarded" else "Locked after inactivity") }
        }
        backgroundSince = 0L
    }

    fun clearMessage() = _ui.update { it.copy(message = null) }
    fun clearError() = _ui.update { it.copy(error = null) }

    override fun onCleared() {
        lock()
        access.closeUsb()
    }
}

/** The user closed the fingerprint / screen-lock prompt. */
class PromptCancelled : Exception("Cancelled")
