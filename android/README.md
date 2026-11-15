# FidoParole — Android

Kotlin + Jetpack Compose, Android 8.0 (API 26) and newer. Keys over **USB**
(USB-C / OTG, HID) and **NFC** (ISO-DEP). All protocol and crypto work happens in
the shared Rust core ([`../core`](../core), via the UniFFI bindings in
[`../ffi`](../ffi)); the app moves bytes and draws the UI.

## Build

Needs: JDK 17, the Android SDK (platform 36) and NDK 27.2.12479018, Rust with
the Android targets, and cargo-ndk:

```bash
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
cargo install cargo-ndk
cd android
./gradlew assembleDebug          # app/build/outputs/apk/debug/app-debug.apk
./gradlew testDebugUnitTest      # JVM tests: Kotlin bindings ↔ Rust, UI screenshots
```

Gradle's `buildRust` task runs `build-rust.sh`, which builds `libfidoparole_ffi.so`
for arm64-v8a, armeabi-v7a and x86_64 with cargo-ndk and generates the Kotlin
bindings into `app/build/generated/uniffi`. Android Studio works the same way
(open the `android/` folder; set `sdk.dir` in `local.properties` if needed).

**Release:** `./gradlew assembleRelease` gives an unsigned, minified APK; sign it
with your keystore (`apksigner`) or configure signing in CI secrets.

## How it talks to the key

| Path | Code | Notes |
|------|------|-------|
| USB | `keys/UsbFido.kt` | HID interface (no boot subclass/protocol) with 64-byte interrupt IN+OUT endpoints; report descriptor checked for the FIDO usage page (0xF1D0). Reads use a queued `UsbRequest` that survives timeouts, so no report is lost. Android asks the user once per key. |
| NFC | `keys/NfcFido.kt` | `IsoDep` in reader mode, enabled while an operation waits for a key **and until it ends** (turning reader mode off invalidates the tag). No touch is needed over NFC; the app says "keep holding" instead. |
| Demo | `KeyLink.demo()` | Software key inside the app (PIN 1234) with a sample vault. |

`KeyAccess.kt` opens links (USB links stay open while the key is plugged in; an NFC
link lives for one tap). `VaultViewModel.kt` runs every key operation off the main
thread; over NFC a save first re-checks that it's the same vault and unchanged.

## Saved PIN

*Save the PIN on this phone* (on the unlock screen) stores the key's PIN encrypted
with an AES-256-GCM key in the Android Keystore (`PinStore.kt`). That key can only be
used right after the phone's fingerprint/face check or screen lock (every time, no
grace period), is destroyed when fingerprints are added or the screen lock removed,
and is never backed up. If the key rejects the saved PIN, it is deleted at once so
no further attempts are spent. One PIN is saved per phone.

The PIN field has a number-pad / full-keyboard switch (FIDO PINs may contain
letters); the choice is remembered. With only 1–2 PIN attempts left, the first tap
on *Unlock* stops with a warning and a second tap is needed.

## Security notes

- `FLAG_SECURE`: no screenshots or app-switcher previews.
- Copied passwords are flagged sensitive (hidden from the clipboard preview) and
  cleared after 30 s.
- Auto-lock after 2 minutes in the background (8 with unsaved changes).
- `allowBackup=false`; nothing is written to storage except backup files you export.
