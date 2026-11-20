package com.token2.fidoparole.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.token2.fidoparole.UiState
import com.token2.fidoparole.VaultViewModel
import com.token2.fidoparole.keys.UsbKey
import uniffi.fidoparole_ffi.EntryField
import uniffi.fidoparole_ffi.GenOptions
import java.text.DateFormat
import java.util.Date

/** Callbacks for system pickers the activity owns (Storage Access Framework). */
class FilePickers(val exportTo: (String, (android.net.Uri) -> Unit) -> Unit, val importFrom: ((android.net.Uri) -> Unit) -> Unit)

@Composable
fun App(vm: VaultViewModel, files: FilePickers) {
    val s by vm.ui.collectAsState()
    val snack = remember { SnackbarHostState() }
    var showAbout by remember { mutableStateOf(false) }
    val onAbout = { showAbout = true }
    LaunchedEffect(s.message) { s.message?.let { snack.showSnackbar(it); vm.clearMessage() } }

    Box(Modifier.fillMaxSize()) {
        when {
            s.status != null && s.entry != null -> EntryScreen(s, vm, snack, onAbout)
            s.status != null -> VaultScreen(s, vm, files, snack, onAbout)
            s.choices != null -> ChooseScreen(s, vm, onAbout)
            else -> StartScreen(s, vm, snack, onAbout)
        }
        if (showAbout) AboutDialog { showAbout = false }
        if (s.editTokenRequired) EditTokenDialog(s, vm)
        s.busy?.let { BusyOverlay(it, onCancel = vm::cancelBusy) }
        s.error?.let { err ->
            AlertDialog(onDismissRequest = vm::clearError, confirmButton = { TextButton(onClick = vm::clearError) { Text("OK") } },
                title = { Text("Couldn't complete that") }, text = { Text(err) })
        }
    }
}

/** Shown only when strong phone biometrics are unavailable. PIN stays in this dialog. */
@Composable
fun EditTokenDialog(s: UiState, vm: VaultViewModel) {
    var pin by remember { mutableStateOf("") }
    var tokenFingerprint by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = vm::cancelEditAuthentication,
        title = { Text("Authenticate with your token") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("Connect your vault's security key by USB or hold it to the phone using NFC. Enter its PIN, or use the key's own fingerprint over USB.")
                KeyPicker(s.usbKeys, s.usbChoice, s.nfcAvailable, vm::chooseUsb, vm::refreshUsb)
                PinField(pin, { pin = it }, "Token PIN", s.pinAlpha, vm::setPinAlpha, enabled = !tokenFingerprint || s.usbChoice == null)
                if (s.usbChoice != null && s.keyInfo?.hasFingerprint != false) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(tokenFingerprint, { tokenFingerprint = it })
                        Text("Use fingerprint on the security key")
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = {
            vm.authenticateEditWithToken(pin, tokenFingerprint && s.usbChoice != null)
            pin = ""
        }) { Text("Authenticate") } },
        dismissButton = { TextButton(onClick = vm::cancelEditAuthentication) { Text("Cancel") } },
    )
}

// ------------------------------------------------------------- start ----

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun StartScreen(s: UiState, vm: VaultViewModel, snack: SnackbarHostState, onAbout: () -> Unit) {
    var pin by remember { mutableStateOf("") }
    var fingerprint by remember { mutableStateOf(false) }
    var newName by remember { mutableStateOf("Personal") }
    var showCreate by remember { mutableStateOf(false) }
    var savePin by remember { mutableStateOf(false) }
    Scaffold(topBar = { TopAppBar(title = { Brandmark() }, actions = { EditModeAction(s, vm); AboutMenuAction(onAbout, if (!s.editing && s.busy == null) vm::requestTokenEditing else null) }) }, snackbarHost = { SnackbarHost(snack) }) { pad ->
        Column(Modifier.padding(pad).padding(horizontal = 20.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(14.dp)) {
            Text("Your passwords, on your key", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.SemiBold)
            Text("Plug in your FIDO2 key, or hold it to the back of the phone when asked.", color = MaterialTheme.colorScheme.secondary)

            Text("Security key", style = MaterialTheme.typography.titleSmall)
            KeyPicker(s.usbKeys, s.usbChoice, s.nfcAvailable, onPick = vm::chooseUsb, onRefresh = vm::refreshUsb)
            if (s.usbChoice != null) {
                s.keyInfo?.let { KeyChips(it) } ?: TextButton(onClick = vm::readKeyInfo) { Text("Check this key") }
            }

            if (s.savedPin && !fingerprint) {
                Button(onClick = vm::unlockWithSavedPin, modifier = Modifier.fillMaxWidth().height(52.dp)) {
                    Icon(Icons.Filled.Fingerprint, null); Spacer(Modifier.width(8.dp)); Text("Unlock with saved PIN")
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("Or type the PIN below.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.secondary, modifier = Modifier.weight(1f))
                    TextButton(onClick = vm::forgetSavedPin) { Text("Forget saved PIN") }
                }
            }
            PinField(pin, { pin = it }, "PIN", s.pinAlpha, vm::setPinAlpha, enabled = !fingerprint)
            if (s.canSavePin && !fingerprint && !s.savedPin) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = savePin, onCheckedChange = { savePin = it })
                    Column {
                        Text("Save the PIN on this phone")
                        Text("Unlock next time with your fingerprint or screen lock", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.secondary)
                    }
                }
            }
            if (s.usbChoice != null && s.keyInfo?.hasFingerprint != false) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = fingerprint, onCheckedChange = { fingerprint = it })
                    Text("Use fingerprint instead of PIN")
                }
            }
            val primary = !(s.savedPin && !fingerprint)
            val unlockAction = { vm.unlock(pin, fingerprint, remember = savePin); pin = "" }
            if (primary) Button(onClick = unlockAction, modifier = Modifier.fillMaxWidth().height(52.dp)) {
                Icon(Icons.Filled.LockOpen, null); Spacer(Modifier.width(8.dp)); Text("Unlock")
            } else OutlinedButton(onClick = unlockAction, modifier = Modifier.fillMaxWidth()) {
                Icon(Icons.Filled.LockOpen, null); Spacer(Modifier.width(8.dp)); Text("Unlock with typed PIN")
            }
            if (s.editing) HorizontalDivider()
            if (s.editing) TextButton(onClick = { showCreate = !showCreate }) { Text(if (showCreate) "Hide" else "Create a new vault on this key…") }
            if (s.editing && showCreate) {
                Text("Makes a vault credential on the key and stores an empty encrypted vault in its largeBlob storage. Uses the PIN above. Over USB the key blinks twice: touch it each time. Over NFC just keep holding it to the phone.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.secondary)
                OutlinedTextField(value = newName, onValueChange = { if (it.toByteArray().size <= 32) newName = it }, label = { Text("Vault name") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                OutlinedButton(onClick = { vm.create(newName, pin, fingerprint); pin = "" }, modifier = Modifier.fillMaxWidth()) { Text("Create vault") }
            }
            HorizontalDivider()
            TextButton(onClick = vm::startDemo) { Icon(Icons.Outlined.Science, null); Spacer(Modifier.width(6.dp)); Text("No key at hand? Try the demo") }
            Spacer(Modifier.height(20.dp))
        }
    }
}

@Composable
fun Brandmark() {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Icon(painterResource(com.token2.fidoparole.R.drawable.ic_mark), null, tint = Color.Unspecified, modifier = Modifier.size(30.dp))
        Spacer(Modifier.width(8.dp))
        Text("Fido", fontWeight = FontWeight.Bold)
        Text("Parole", fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.primary)
    }
}

@Composable
private fun painterResource(id: Int) = androidx.compose.ui.res.painterResource(id)

@Composable
fun KeyPicker(keys: List<UsbKey>, chosen: String?, nfc: Boolean, onPick: (String?) -> Unit, onRefresh: () -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        keys.forEach { k ->
            KeyRow(selected = chosen == k.id, icon = Icons.Filled.Usb, title = k.label,
                subtitle = listOfNotNull("USB", k.serial?.let { "S/N $it" }).joinToString(" · ")) { onPick(k.id) }
        }
        KeyRow(selected = chosen == null, icon = Icons.Filled.Nfc, title = "NFC",
            subtitle = if (nfc) "Hold the key to the back of the phone when asked" else "This phone has no NFC, or it is turned off") { onPick(null) }
        TextButton(onClick = onRefresh) { Icon(Icons.Filled.Refresh, null); Spacer(Modifier.width(6.dp)); Text("Look for USB keys again") }
    }
}

@Composable
fun KeyRow(selected: Boolean, icon: androidx.compose.ui.graphics.vector.ImageVector, title: String, subtitle: String, onClick: () -> Unit) {
    OutlinedCard(onClick = onClick, border = if (selected) CardDefaults.outlinedCardBorder().copy(width = 2.dp, brush = androidx.compose.ui.graphics.SolidColor(MaterialTheme.colorScheme.primary)) else CardDefaults.outlinedCardBorder(),
        modifier = Modifier.fillMaxWidth()) {
        Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(icon, null, tint = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.secondary)
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(title, fontWeight = FontWeight.SemiBold)
                Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.secondary)
            }
            RadioButton(selected = selected, onClick = onClick)
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun KeyChips(i: uniffi.fidoparole_ffi.KeyInfo) {
    FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        AssistChip(onClick = {}, label = { Text(if (i.hmacSecret) "✓ hmac-secret" else "✕ hmac-secret") })
        AssistChip(onClick = {}, label = { Text(if (i.largeBlob) "✓ largeBlob · ${i.maxLargeBlob} B" else "✕ largeBlob") })
        AssistChip(onClick = {}, label = { Text(if (i.hasPin) "✓ PIN set" else "✕ No PIN") })
        if (i.hasFingerprint) AssistChip(onClick = {}, label = { Text("✓ Fingerprint") })
        if (i.pinRetries >= 0) AssistChip(onClick = {}, label = { Text("${i.pinRetries} PIN tries left") })
    }
    i.problem?.let { Text(it, color = MaterialTheme.colorScheme.error) }
}

@Composable
fun EditModeAction(s: UiState, vm: VaultViewModel) {
    TextButton(onClick = { if (s.editing) vm.finishEditing() else vm.enableEditing() }, enabled = s.busy == null && !s.editAuthenticating) {
        Text(if (s.editAuthenticating) "Authenticating…" else if (s.editing) "Done" else "Edit")
    }
}

// ------------------------------------------------------------ choose ----

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChooseScreen(s: UiState, vm: VaultViewModel, onAbout: () -> Unit) {
    Scaffold(topBar = { TopAppBar(title = { Text("Choose a vault") }, navigationIcon = {
        IconButton(onClick = vm::cancelChoose) { Icon(Icons.Filled.Close, "Cancel") } }, actions = { AboutMenuAction(onAbout, if (!s.editing && s.busy == null) vm::requestTokenEditing else null) }) }) { pad ->
        LazyColumn(Modifier.padding(pad)) {
            itemsIndexed(s.choices.orEmpty()) { i, (name, _) ->
                ListItem(headlineContent = { Text(name) }, leadingContent = { Icon(Icons.Filled.Lock, null) },
                    modifier = Modifier.clickableRow { vm.choose(i) })
                HorizontalDivider()
            }
        }
    }
}

private fun <T> androidx.compose.foundation.lazy.LazyListScope.itemsIndexed(list: List<T>, content: @Composable (Int, T) -> Unit) {
    items(list.size) { i -> content(i, list[i]) }
}

private fun Modifier.clickableRow(onClick: () -> Unit) = this.clickable(onClick = onClick)

// ------------------------------------------------------------- vault ----

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VaultScreen(s: UiState, vm: VaultViewModel, files: FilePickers, snack: SnackbarHostState, onAbout: () -> Unit) {
    val st = s.status ?: return
    var menu by remember { mutableStateOf(false) }
    var dialog by remember { mutableStateOf<String?>(null) }
    Scaffold(
        topBar = {
            TopAppBar(title = { Column { Text(st.name, fontWeight = FontWeight.SemiBold); Text("${st.entryCount} entries · ${if (s.editing) "Editing" else "Read-only"}", style = MaterialTheme.typography.bodySmall) } },
                actions = {
                    EditModeAction(s, vm)
                    IconButton(onClick = vm::lock) { Icon(Icons.Filled.Lock, "Lock") }
                    IconButton(onClick = { menu = true }) { Icon(Icons.Filled.MoreVert, "More") }
                    DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                        if (s.editing) DropdownMenuItem(text = { Text("Save to key") }, onClick = { menu = false; vm.save() })
                        if (s.editing) DropdownMenuItem(text = { Text("Copy vault to another key…") }, onClick = { menu = false; dialog = "copy" })
                        DropdownMenuItem(text = { Text("Export encrypted backup…") }, onClick = { menu = false; dialog = "export" })
                        if (s.editing) DropdownMenuItem(text = { Text("Import backup…") }, onClick = { menu = false; dialog = "import" })
                        if (s.editing) HorizontalDivider()
                        if (s.editing) DropdownMenuItem(text = { Text("Delete vault from key…", color = MaterialTheme.colorScheme.error) }, onClick = { menu = false; dialog = "delete" })
                        HorizontalDivider()
                        if (!s.editing) DropdownMenuItem(text = { Text("Edit with token PIN") }, onClick = { menu = false; vm.requestTokenEditing() })
                        DropdownMenuItem(text = { Text("About / Info") }, onClick = { menu = false; onAbout() })
                    }
                })
        },
        floatingActionButton = { if (s.editing) FloatingActionButton(onClick = vm::addEntry, containerColor = MaterialTheme.colorScheme.primary) { Icon(Icons.Filled.Add, "New entry") } },
        snackbarHost = { SnackbarHost(snack) },
    ) { pad ->
        Column(Modifier.padding(pad)) {
            if (st.max > 0u) StorageBar(st.used.toLong(), st.max.toLong())
            if (s.editing && st.dirty) {
                Surface(color = Color(0xFFFFF8E6), modifier = Modifier.fillMaxWidth()) {
                    Row(Modifier.padding(horizontal = 16.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                        Text("Unsaved changes — only in memory until you save them to the key.", color = Color(0xFF7A5A00), style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1f))
                        Button(onClick = vm::save, contentPadding = PaddingValues(horizontal = 14.dp)) { Text("Save") }
                    }
                }
            }
            OutlinedTextField(value = s.query, onValueChange = vm::search, placeholder = { Text("Search") }, singleLine = true,
                leadingIcon = { Icon(Icons.Filled.Search, null) }, modifier = Modifier.fillMaxWidth().padding(16.dp))
            if (s.entries.isEmpty()) {
                Text(when {
                    s.query.isNotEmpty() -> "No matches."
                    s.editing -> "No entries yet. Tap + to add one."
                    else -> "No entries in this vault."
                }, color = MaterialTheme.colorScheme.secondary,
                    modifier = Modifier.fillMaxWidth().padding(32.dp), textAlign = TextAlign.Center)
            }
            LazyColumn(contentPadding = PaddingValues(bottom = 88.dp)) {
                items(s.entries, key = { it.id }) { e ->
                    ListItem(headlineContent = { Text(e.title.ifEmpty { "(untitled)" }) },
                        supportingContent = { Text(e.username.ifEmpty { e.url }, maxLines = 1) },
                        leadingContent = { Avatar(e.title) },
                        modifier = Modifier.clickableRow { vm.openEntry(e.id) })
                }
            }
        }
    }
    when (dialog) {
        "copy" -> CopyDialog(s, st.name, onDismiss = { dialog = null }) { usb, pin, name -> dialog = null; vm.copyToOtherKey(usb, pin, name) }
        "export" -> PassphraseDialog("Export encrypted backup", "The file is protected by this passphrase (Argon2id + AES-256-GCM) and opens without any security key — keep file and passphrase apart.",
            confirm = "Choose file…", repeat = true, onDismiss = { dialog = null }) { pass, _ -> dialog = null; files.exportTo("${st.name}.t2vault") { uri -> vm.exportBackup(uri, pass) } }
        "import" -> PassphraseDialog("Import backup", "Pick a .t2vault file and enter its passphrase.", confirm = "Choose file…", repeat = false, mergeOption = true,
            onDismiss = { dialog = null }) { pass, replace -> dialog = null; files.importFrom { uri -> vm.importBackup(uri, pass, replace) } }
        "delete" -> DeleteDialog(st.name, st.entryCount.toInt(), st.dirty, onDismiss = { dialog = null },
            onExport = { dialog = "export" }) { dialog = null; vm.deleteVault() }
    }
}

@Composable
fun StorageBar(used: Long, max: Long) {
    val f = (used.toFloat() / max).coerceIn(0f, 1f)
    Column(Modifier.padding(horizontal = 16.dp, vertical = 6.dp)) {
        LinearProgressIndicator(progress = { f }, modifier = Modifier.fillMaxWidth().height(6.dp).clip(CircleShape),
            color = if (f > 0.92f) MaterialTheme.colorScheme.error else if (f > 0.75f) Color(0xFFB54708) else Color(0xFF067647),
            trackColor = MaterialTheme.colorScheme.surfaceVariant, gapSize = 0.dp, drawStopIndicator = {})
        Text("Key storage: $used / $max bytes", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.secondary)
    }
}

@Composable
fun Avatar(title: String) {
    Box(Modifier.size(36.dp).clip(CircleShape), contentAlignment = Alignment.Center) {
        Surface(color = MaterialTheme.colorScheme.primaryContainer, modifier = Modifier.fillMaxSize()) {}
        Text(title.trim().take(1).uppercase().ifEmpty { "?" }, color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.Bold)
    }
}

// ------------------------------------------------------------- entry ----

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EntryScreen(s: UiState, vm: VaultViewModel, snack: SnackbarHostState, onAbout: () -> Unit) {
    val e = s.entry ?: return
    var gen by remember { mutableStateOf(false) }
    var confirmDelete by remember { mutableStateOf(false) }
    Scaffold(
        topBar = {
            TopAppBar(title = { Text(e.title.ifEmpty { "Entry" }) },
                navigationIcon = { IconButton(onClick = vm::closeEntry) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back") } },
                actions = {
                    EditModeAction(s, vm)
                    if (s.editing) IconButton(onClick = { confirmDelete = true }) { Icon(Icons.Outlined.Delete, "Delete entry") }
                    AboutMenuAction(onAbout, if (!s.editing && s.busy == null) vm::requestTokenEditing else null)
                })
        },
        snackbarHost = { SnackbarHost(snack) },
    ) { pad ->
        Column(Modifier.padding(pad).padding(16.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Field("Title", e.title, readOnly = !s.editing) { vm.update(EntryField.TITLE, it) }
            Field("Username", e.username, readOnly = !s.editing, onCopy = { vm.copy(EntryField.USERNAME) }) { vm.update(EntryField.USERNAME, it) }
            // Password: hidden until "show"; editing works on the revealed text.
            OutlinedTextField(
                value = s.revealed ?: if (e.hasPassword) "••••••••••••" else "",
                onValueChange = { if (s.editing && (s.revealed != null || !e.hasPassword)) vm.update(EntryField.PASSWORD, it) },
                label = { Text("Password") }, singleLine = true, readOnly = !s.editing || (s.revealed == null && e.hasPassword),
                textStyle = LocalTextStyle.current.copy(fontFamily = FontFamily.Monospace),
                visualTransformation = VisualTransformation.None,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false),
                trailingIcon = {
                    Row {
                        IconButton(onClick = vm::toggleReveal) { Icon(if (s.revealed == null) Icons.Filled.Visibility else Icons.Filled.VisibilityOff, "Show / hide") }
                        IconButton(onClick = { vm.copy(EntryField.PASSWORD) }) { Icon(Icons.Filled.ContentCopy, "Copy password") }
                    }
                },
                modifier = Modifier.fillMaxWidth())
            if (s.editing) OutlinedButton(onClick = { gen = true }) { Icon(Icons.Filled.Casino, null); Spacer(Modifier.width(6.dp)); Text("Generate password") }
            Field("URL", e.url, readOnly = !s.editing, keyboard = KeyboardType.Uri, onCopy = { vm.copy(EntryField.URL) }) { vm.update(EntryField.URL, it) }
            Field("Notes", e.notes, readOnly = !s.editing, single = false) { vm.update(EntryField.NOTES, it) }
            Text("Modified ${DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(e.modified * 1000))}",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.secondary)
            if (s.editing && s.status?.dirty == true) Button(onClick = vm::save, modifier = Modifier.fillMaxWidth()) { Text("Save to key") }
        }
    }
    if (gen) GeneratorDialog(onDismiss = { gen = false }) { gen = false; vm.generate(it) }
    if (confirmDelete) AlertDialog(onDismissRequest = { confirmDelete = false },
        title = { Text("Delete this entry?") }, text = { Text("It is removed from the vault when you next save to the key.") },
        confirmButton = { TextButton(onClick = { confirmDelete = false; vm.deleteEntry() }) { Text("Delete", color = MaterialTheme.colorScheme.error) } },
        dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text("Cancel") } })
}

@Composable
fun Field(label: String, value: String, single: Boolean = true, readOnly: Boolean = false, keyboard: KeyboardType = KeyboardType.Text, onCopy: (() -> Unit)? = null, onChange: (String) -> Unit) {
    OutlinedTextField(value = value, onValueChange = onChange, readOnly = readOnly, label = { Text(label) }, singleLine = single, minLines = if (single) 1 else 3,
        keyboardOptions = KeyboardOptions(keyboardType = keyboard),
        trailingIcon = onCopy?.let { { IconButton(onClick = it) { Icon(Icons.Filled.ContentCopy, "Copy") } } },
        modifier = Modifier.fillMaxWidth())
}

// ----------------------------------------------------------- dialogs ----

@Composable
fun GeneratorDialog(onDismiss: () -> Unit, onGenerate: (GenOptions) -> Unit) {
    var len by remember { mutableFloatStateOf(20f) }
    var upper by remember { mutableStateOf(true) }
    var lower by remember { mutableStateOf(true) }
    var digits by remember { mutableStateOf(true) }
    var symbols by remember { mutableStateOf(true) }
    AlertDialog(onDismissRequest = onDismiss, title = { Text("Generate password") },
        text = {
            Column {
                Text("Length: ${len.toInt()}")
                Slider(value = len, onValueChange = { len = it }, valueRange = 8f..64f)
                listOf("A–Z" to upper, "a–z" to lower, "0–9" to digits, "Symbols" to symbols).forEachIndexed { i, (t, v) ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = v, onCheckedChange = { c -> when (i) { 0 -> upper = c; 1 -> lower = c; 2 -> digits = c; else -> symbols = c } })
                        Text(t)
                    }
                }
            }
        },
        confirmButton = { TextButton(enabled = upper || lower || digits || symbols, onClick = { onGenerate(GenOptions(len.toInt().toUInt(), upper, lower, digits, symbols)) }) { Text("Generate") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } })
}

@Composable
fun PassphraseDialog(title: String, hint: String, confirm: String, repeat: Boolean, mergeOption: Boolean = false, onDismiss: () -> Unit, onOk: (String, Boolean) -> Unit) {
    var a by remember { mutableStateOf("") }
    var b by remember { mutableStateOf("") }
    var replace by remember { mutableStateOf(false) }
    val err = when {
        repeat && a.length in 1..9 -> "Use at least 10 characters."
        repeat && b.isNotEmpty() && a != b -> "The passphrases differ."
        else -> null
    }
    AlertDialog(onDismissRequest = onDismiss, title = { Text(title) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(hint, style = MaterialTheme.typography.bodySmall)
                OutlinedTextField(value = a, onValueChange = { a = it }, label = { Text("Passphrase") }, singleLine = true, visualTransformation = PasswordVisualTransformation())
                if (repeat) OutlinedTextField(value = b, onValueChange = { b = it }, label = { Text("Repeat passphrase") }, singleLine = true, visualTransformation = PasswordVisualTransformation())
                if (mergeOption) {
                    Row(verticalAlignment = Alignment.CenterVertically) { RadioButton(!replace, { replace = false }); Text("Merge (newest copy of each entry wins)") }
                    Row(verticalAlignment = Alignment.CenterVertically) { RadioButton(replace, { replace = true }); Text("Replace this vault") }
                }
                err?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            }
        },
        confirmButton = { TextButton(enabled = a.isNotEmpty() && err == null && (!repeat || a == b), onClick = { onOk(a, replace) }) { Text(confirm) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } })
}

@Composable
fun CopyDialog(s: UiState, vaultName: String, onDismiss: () -> Unit, onCopy: (UsbKey?, String, String) -> Unit) {
    var target by remember { mutableStateOf<String?>(null) }
    var pin by remember { mutableStateOf("") }
    var alpha by remember { mutableStateOf(s.pinAlpha) }
    var name by remember { mutableStateOf(vaultName) }
    AlertDialog(onDismissRequest = onDismiss, title = { Text("Copy vault to another key") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text("1. Unplug this key if it's on USB — the vault stays open in memory.\n2. Choose the target key below.\n3. Enter the target key's PIN and press Copy.\n4. The target key blinks twice: touch it each time (over NFC just keep holding it). Don't remove it until FidoParole is done.",
                    style = MaterialTheme.typography.bodySmall)
                KeyPicker(s.usbKeys, target, s.nfcAvailable, onPick = { target = it }, onRefresh = {})
                OutlinedTextField(value = name, onValueChange = { if (it.toByteArray().size <= 32) name = it }, label = { Text("Vault name") }, singleLine = true)
                PinField(pin, { pin = it }, "Target key PIN", alpha, { alpha = it })
            }
        },
        confirmButton = { TextButton(enabled = pin.isNotEmpty() && name.isNotBlank(), onClick = { onCopy(s.usbKeys.firstOrNull { it.id == target }, pin, name) }) { Text("Copy") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } })
}

@Composable
fun DeleteDialog(name: String, count: Int, dirty: Boolean, onDismiss: () -> Unit, onExport: () -> Unit, onDelete: () -> Unit) {
    var ack by remember { mutableStateOf(false) }
    var typed by remember { mutableStateOf("") }
    val expected = name.ifEmpty { "DELETE" }
    AlertDialog(onDismissRequest = onDismiss, title = { Text("Delete this vault from the key?") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Surface(color = Color(0xFFFFF3F3), shape = MaterialTheme.shapes.small) {
                    Text("This permanently erases “$name” ($count ${if (count == 1) "entry" else "entries"}) from the key: the encrypted data and the vault credential. It takes effect immediately and cannot be undone.",
                        color = Color(0xFF8A1F1F), modifier = Modifier.padding(10.dp))
                }
                Text("Copies on other keys and backup files are not affected. Without one of those, nobody can recover these passwords.", style = MaterialTheme.typography.bodySmall)
                if (dirty) Text("There are unsaved changes.", fontWeight = FontWeight.SemiBold)
                OutlinedButton(onClick = onExport) { Text("Export a backup first…") }
                Row(verticalAlignment = Alignment.CenterVertically) { Checkbox(ack, { ack = it }); Text("I have a backup or a copy, or I accept losing these passwords", style = MaterialTheme.typography.bodySmall) }
                OutlinedTextField(value = typed, onValueChange = { typed = it }, label = { Text("Type $expected to confirm") }, singleLine = true)
            }
        },
        confirmButton = { TextButton(enabled = ack && typed.trim() == expected, onClick = onDelete) { Text("Delete permanently", color = MaterialTheme.colorScheme.error) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } })
}

@Composable
fun BusyOverlay(b: com.token2.fidoparole.Busy, onCancel: () -> Unit) {
    Dialog(onDismissRequest = {}) {
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(24.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(14.dp)) {
                Box(Modifier.size(72.dp).clip(CircleShape), contentAlignment = Alignment.Center) {
                    Surface(color = MaterialTheme.colorScheme.primaryContainer, modifier = Modifier.fillMaxSize()) {}
                    Icon(if (b.nfc) Icons.Filled.Nfc else Icons.Filled.TouchApp, null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(38.dp))
                }
                if (b.touch && !b.nfc) AssistChip(onClick = {}, label = { Text("Touch the key now") })
                Text(b.text, textAlign = TextAlign.Center, fontWeight = FontWeight.Medium)
                LinearProgressIndicator(Modifier.fillMaxWidth())
                if (b.waitingForTag) TextButton(onClick = onCancel) { Text("Cancel") }
            }
        }
    }
}

@Composable
private fun Dialog(onDismissRequest: () -> Unit, content: @Composable () -> Unit) =
    androidx.compose.ui.window.Dialog(onDismissRequest = onDismissRequest,
        properties = androidx.compose.ui.window.DialogProperties(dismissOnBackPress = false, dismissOnClickOutside = false), content = content)

/**
 * PIN entry with a number-pad / full-keyboard switch (FIDO PINs may contain
 * letters). Switching keeps the focus so the new keyboard comes up at once.
 */
@Composable
fun PinField(value: String, onChange: (String) -> Unit, label: String, alpha: Boolean, onAlpha: (Boolean) -> Unit, enabled: Boolean = true) {
    val focus = remember { FocusRequester() }
    var switched by remember { mutableStateOf(false) }
    var shown by remember { mutableStateOf(false) }
    key(alpha) {
        OutlinedTextField(
            value = value, onValueChange = onChange, label = { Text(label) }, singleLine = true, enabled = enabled,
            visualTransformation = if (shown) VisualTransformation.None else PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = if (alpha) KeyboardType.Password else KeyboardType.NumberPassword, autoCorrectEnabled = false),
            trailingIcon = {
                Row {
                    IconButton(onClick = { shown = !shown }, enabled = enabled) {
                        Icon(if (shown) Icons.Filled.VisibilityOff else Icons.Filled.Visibility, if (shown) "Hide PIN" else "Show PIN")
                    }
                    IconButton(onClick = { switched = true; onAlpha(!alpha) }, enabled = enabled) {
                        Icon(if (alpha) Icons.Filled.Dialpad else Icons.Filled.Keyboard, if (alpha) "Use number pad" else "Use full keyboard (letters)")
                    }
                }
            },
            supportingText = { Text(if (alpha) "Letters and numbers — tap the dial pad for digits only" else "Digits — tap the keyboard icon if your PIN has letters") },
            modifier = Modifier.fillMaxWidth().focusRequester(focus),
        )
    }
    LaunchedEffect(alpha) { if (switched) { focus.requestFocus(); switched = false } }
}
