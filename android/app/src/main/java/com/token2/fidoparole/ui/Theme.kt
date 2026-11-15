package com.token2.fidoparole.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

val Brand = Color(0xFFF23058)
val BrandDark = Color(0xFFD81F45)

private val Light = lightColorScheme(
    primary = Brand, onPrimary = Color.White, primaryContainer = Color(0xFFFFE0E7), onPrimaryContainer = Color(0xFF5C0A1E),
    secondary = Color(0xFF5B636E), background = Color.White, surface = Color.White, surfaceVariant = Color(0xFFF5F7F9),
    error = Color(0xFFC01048),
)
private val Dark = darkColorScheme(
    primary = Color(0xFFFF5C7C), onPrimary = Color(0xFF3A0010), primaryContainer = Color(0xFF7A1530), onPrimaryContainer = Color(0xFFFFD9E0),
    background = Color(0xFF16181D), surface = Color(0xFF16181D), surfaceVariant = Color(0xFF22252B),
)

@Composable
fun FidoParoleTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = if (isSystemInDarkTheme()) Dark else Light, content = content)
}
