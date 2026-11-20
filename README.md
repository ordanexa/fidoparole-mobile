# Ordanexa Android fork

## Project status

Version names retain the upstream base followed by the Ordanexa revision: `0.3.0-ordanexa.0.1.3`. The previous `1.0.0` name did not show that base and is retained only as historical release numbering. Android versionCode continues increasing, so existing installations can update normally.

**Stable release: 1.0.0.** The feature scope is **frozen**. The agreed Android feature set is complete. Future maintenance is limited to bug fixes, security fixes, Android compatibility and necessary upstream updates. New features require a separate decision; document/file-vault tools are outside this project's scope.

This fork of [Token2 FidoParole Mobile](https://github.com/token2/fidoparole-mobile) adds a read-only default to the Android app.

- **More → About / Info** is available on the start, vault selection, vault and entry screens, including while locked. It shows the installed version, Read-only/Edit and NFC guidance, project links and MIT license credits.
- Opened vaults start in **Read-only** mode. Browse, search, show/hide and copy work immediately. Encrypted backup export is also available.
- Choose **Edit** and complete a fresh phone fingerprint authentication to enable changes. Phone fingerprint works without the token present. **Use token PIN** in the fingerprint prompt and **More → Edit with token PIN** are always available, even when phone biometrics are enrolled. Connect the vault's token over USB/NFC and authenticate with its PIN (or the token's fingerprint over USB). Without usable phone biometrics, Edit opens the token prompt directly. The device screen-lock PIN is not an Edit fallback. A saved token PIN is not required. Cancelling or failing authentication keeps Read-only active. Entry fields, password generation, add/delete, save, import, copy-to-another-key, vault creation and deletion are guarded in the Android ViewModel as well as the UI.
- A successful save returns to Read-only. **Done** also returns to Read-only when there are no unsaved changes. With unsaved changes, save first or lock the vault to discard them.
- Opening another vault, locking, backgrounding the app or detaching a USB key resets the Edit permission. NFC is connected only during individual operations: removing an NFC key between operations does not revoke Edit. Hold it to the phone again to save; Save, Done (when clean), Lock and backgrounding end Edit. Pending authentication cannot restore an expired session. This mode prevents accidental application writes. It does not change the token's firmware or enforce a protocol-level read-only mode.

Android stable release **1.0.0** uses package `com.ordanexa.fidoparole.mobile` and launcher name **FidoParole Ordanexa**, so it can be installed alongside the official app. The fork has its own app data and PIN storage.

| Variant | Download | Size | Architectures |
| --- | --- | --- | --- |
| **ARM64 (recommended for current Samsung devices)** | [ARM64 APK](apks/fidoparole-mobile-ordanexa-1.0.0-arm64.apk?raw=true) | 3.60 MiB | arm64-v8a |
| Universal | [Universal APK](apks/fidoparole-mobile-ordanexa-1.0.0-universal.apk?raw=true) | 5.71 MiB | arm64-v8a, armeabi-v7a, x86_64 |

[Stable releases](https://github.com/ordanexa/fidoparole-mobile/releases) · [Changelog](CHANGELOG.md) · [SHA-256 checksums](apks/SHA256SUMS) · [Previous test APKs](apks/)

Validation passed in [build run 44776876199](https://github.com/ordanexa/fidoparole-android-reader/actions/runs/44776876199): **24 Rust tests and all 11 Android tests**, including fresh Edit authentication, token fallback with wrong-PIN rejection, session revocation, ViewModel mutation guards and Compose UI checks for About / Info on the start, vault and entry screens. Both release APKs' package, version, architecture sets, signing certificate and 16 KiB ZIP alignment were verified. Source commit: `1accf2ec3583698f443e976b14edcbe2dfdde18a`.

The token fallback verifies the open vault's credential and hmac-secret through a fresh authentication; it does not write to the token or replace unsaved entries. Phone-fingerprint Edit needs no token connection. Saving still requires the vault's token.

Physical-device testing of the Edit authentication over USB and NFC remains unverified in this release record. This version-only promotion adds no new physical-device test. Vault unlocking and the NFC transport are inherited from upstream.

## Android build variants

`cd android && ./gradlew assembleRelease` produces the ARM64-only and Universal APKs in one build. Both use the same package, version and signing certificate; install either variant. Signed builds use the existing signing secrets in the Reader repository's [Mobile build workflow](https://github.com/ordanexa/fidoparole-android-reader/blob/build/mobile-read-only-0.1.0/.github/workflows/mobile-read-only-test.yml). No signing keys are stored in this fork.

## Android device check

1. Open a vault by USB, then NFC. Confirm Read-only is shown and no add, generate, save, import or delete action is offered.
2. Open an entry. Show/hide and copy its password. Confirm touching the displayed fields cannot edit them.
3. Choose Edit, authenticate again using phone fingerprint (without needing the token), or with the token when phone biometrics are unavailable, modify a dummy entry and save. Confirm the vault returns to Read-only and can be reopened with the change.
4. Choose Edit without changing anything, then Done. Confirm Read-only resumes.
5. Make an unsaved edit, then Done. Confirm the app asks you to save or lock instead of losing the edit.
6. Cancel the Edit prompt; confirm edits remain blocked. Enable Edit, background/return to the app, then repeat with USB removal; confirm a new authentication is required each time.
7. Open More → About / Info before unlocking, in a vault and on an entry. Confirm the current version and Read-only/Edit/NFC guidance are shown. Close it and confirm the screen and Edit permission are unchanged.
8. Lock and reopen. Confirm Read-only is restored. Test backup export in Read-only and import/copy-to-key only after Edit using test data and a backup key.

---

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo/wordmark-dark.svg">
    <img src="assets/logo/wordmark.svg" alt="FidoParole" width="420">
  </picture>
</p>

<p align="center"><b>Your passwords, stored on your FIDO2 security key — on Android and iPhone.</b></p>

# FidoParole Mobile

The Android and iOS apps of [FidoParole](https://github.com/token2/fidoparole).
There is no vault file on the phone and no cloud: the encrypted vault lives in the
security key's own largeBlob storage, and only that key (with its PIN or
fingerprint) can decrypt it. The vaults are the same ones the Windows, Linux and
macOS app creates — plug the key into a laptop or hold it to a phone.

> **Status: proof of concept.** Android works on real phones over USB; NFC is being
> tested. The iOS app has not been tried on an iPhone yet.

## What it does

- **Unlock** a vault with the key's PIN (or its fingerprint, over USB), browse,
  search, add and edit entries, generate passwords, and **save back** to the key.
- **USB-C** (Android) and **NFC** (Android and iPhone): hold the key to the phone and
  keep it there until the app says it's done — there's no touch over NFC.
- **Saved PIN** (Android): optionally keep the PIN on the phone, unlocked by your
  fingerprint or screen lock (Android Keystore). Removed automatically if the key
  ever rejects it.
- **PIN keyboard switch:** number pad or full keyboard, for PINs with letters.
- **Low-PIN guard:** with 1–2 attempts left the app warns before trying.
- **Copy** the vault to another key, **export/import** encrypted backup files.
- **Demo mode** (PIN 1234) with a software key and a sample vault.
- Screenshots blocked, copied passwords cleared after 30 s, auto-lock in the
  background.

Capacity depends on the key: 1 KB of largeBlob holds about 15–20 entries,
2 KB about 50.

## Layout

```
core/      Rust: vault format + CTAP2 client (CTAPHID over USB, ISO 7816 over NFC,
           PIN/UV protocols 1 and 2, hmac-secret, largeBlob). No C dependencies.
ffi/       UniFFI bindings (Kotlin and Swift) over core
android/   Kotlin + Jetpack Compose app (Android 8+)        → android/README.md
ios/       SwiftUI app with Core NFC (iOS 16+)              → ios/README.md
tools/     crosscheck.py (core vs python-fido2), sim/ (independent CTAP simulator)
```

## Build

**Android** (Linux, macOS or WSL; JDK 17, Android SDK 36, NDK 27.2.12479018):

```bash
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
cargo install cargo-ndk
cd android && ./gradlew assembleDebug
```

**iOS** (macOS with Xcode 16): see [ios/README.md](ios/README.md).

Or let GitHub Actions do it: every push builds the Android APK and the iOS app
(see the *Actions* tab; the APK is attached to each run).

## Tests

```bash
cargo test --workspace                       # vault format, CTAP flows over HID and NFC framing
pip install fido2 && cargo build -p fidoparole-core --example mock_server --features mock \
  && python3 tools/crosscheck.py target/debug/examples/mock_server
pip install -r tools/sim/requirements.txt    # independent simulator, incl. rejection cases
cargo run -p fidoparole-core --features mock --example sim_check -- tools/sim/authenticator.py
cd android && ./gradlew testDebugUnitTest    # Kotlin bindings ↔ Rust, UI screenshots
```

## On-key format

Shared with the desktop app, so every vault opens everywhere: one discoverable
credential per vault under RP id `fido2-vault.token2` (credProtect 3), a fixed
hmac-secret salt, `HKDF-SHA256 → AES-256-GCM` over the deflated JSON vault
(`T2VLT` v1 header), stored in the credential's largeBlob entry. Details in
[`core/src/vault.rs`](core/src/vault.rs) and
[`core/src/keyops.rs`](core/src/keyops.rs).

## Credits

Thanks to **[ordanexa/fidoparole-android-reader](https://github.com/ordanexa/fidoparole-android-reader)**, project 
for independent Android reader for FidoParole vaults before this app existed and shared
it with Token2. From his work we took:

- the **independent CTAP simulator** (`tools/sim/authenticator.py`, built on Yubico's
  python-fido2), which now checks this app's Rust client, including its rejection
  cases (wrong PIN, bad checksum, missing user verification, tampered vault);
- **queued USB reads** (`UsbRequest`) instead of blocking reads with a timeout, and
  matching FIDO HID interfaces only (no boot keyboards or mice);
- the **low-PIN-attempts guard**;
- **stricter checks on the key's answers** (RP id hash, user present, user verified).

python-fido2 is © Yubico AB, BSD 2-clause.

## License

MIT — see [LICENSE](LICENSE).
