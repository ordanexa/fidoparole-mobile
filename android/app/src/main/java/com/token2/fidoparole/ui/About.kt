package com.token2.fidoparole.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.unit.dp
import com.token2.fidoparole.BuildConfig

/** The same information is available before and after unlocking a vault. */
@Composable
fun AboutMenuAction(onAbout: () -> Unit, onTokenEdit: (() -> Unit)? = null) {
    var expanded by remember { mutableStateOf(false) }
    Box {
        IconButton(onClick = { expanded = true }) { Icon(Icons.Filled.MoreVert, "More") }
        DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            onTokenEdit?.let { action ->
                DropdownMenuItem(text = { Text("Edit with token PIN") }, onClick = { expanded = false; action() })
            }
            DropdownMenuItem(text = { Text("About / Info") }, onClick = { expanded = false; onAbout() })
        }
    }
}

@Composable
fun AboutDialog(onClose: () -> Unit) {
    val uriHandler = LocalUriHandler.current
    AlertDialog(
        onDismissRequest = onClose,
        title = { Text("About / Info") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("FidoParole Ordanexa", style = MaterialTheme.typography.titleMedium)
                Text("Version ${BuildConfig.VERSION_NAME}")
                Text("Community fork of Token2 FidoParole Mobile.")
                HorizontalDivider()
                Text("Read-only by default", style = MaterialTheme.typography.titleSmall)
                Text("Browse, search, reveal and copy passwords. Your vault stays on your security key.")
                Text("Edit", style = MaterialTheme.typography.titleSmall)
                Text("Scan your phone's fingerprint to allow changes without a token connection, or choose Use token PIN in the fingerprint prompt. Token authentication is always available, including when phone biometrics are set up. You can also choose More → Edit with token PIN directly. It uses the vault's token PIN or the token's own fingerprint over USB.")
                Text("Save and lock", style = MaterialTheme.typography.titleSmall)
                Text("Saving requires your vault's token. Save, Lock, leaving the app or unplugging a USB token ends Edit. Done returns to Read-only when there are no unsaved changes. Otherwise, save first or lock to discard them.")
                Text("Using NFC", style = MaterialTheme.typography.titleSmall)
                Text("NFC connects only for individual operations. Removing the token between taps keeps Edit active. Hold the token to the phone again when saving.")
                HorizontalDivider()
                Text("Open source · MIT License · Copyright © 2026 Token2")
                TextButton(onClick = { uriHandler.openUri("https://github.com/ordanexa/fidoparole-mobile") }) { Text("Ordanexa fork") }
                TextButton(onClick = { uriHandler.openUri("https://github.com/token2/fidoparole-mobile") }) { Text("Original project — Token2") }
                TextButton(onClick = { uriHandler.openUri("https://github.com/ordanexa/fidoparole-mobile/blob/main/LICENSE") }) { Text("MIT License") }
            }
        },
        confirmButton = { TextButton(onClick = onClose) { Text("Close") } },
    )
}
