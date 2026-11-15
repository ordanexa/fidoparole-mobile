# FidoParole — iPhone

SwiftUI, iOS 16 and newer. Keys over **NFC** (CoreNFC, ISO 7816 with the FIDO
applet id). iOS gives apps no access to FIDO keys over USB-C or Lightning, so USB
is not available on iPhone. All protocol and crypto work happens in the shared Rust
core ([`../core`](../core) via [`../ffi`](../ffi)).

## Build (on a Mac)

Needs: Xcode 16+, Rust with the iOS targets, and XcodeGen:

```bash
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
brew install xcodegen
cd ios
./build-rust.sh        # → Frameworks/FidoParoleFFI.xcframework + Generated/fidoparole_ffi.swift
xcodegen               # → FidoParole.xcodeproj (from project.yml)
open FidoParole.xcodeproj
```

Choose your team under *Signing & Capabilities*. NFC tag reading needs a paid
Apple developer account (the *Near Field Communication Tag Reading* capability),
and it only works on a real iPhone, not in the simulator — the simulator is fine
for the demo key.

Re-run `./build-rust.sh` after changing anything in `core/` or `ffi/`.

## Files

| File | What |
|------|------|
| `project.yml` | XcodeGen spec: target, entitlements (NFC TAG), Info.plist (NFC usage text, FIDO AID `A0000006472F0001`) |
| `build-rust.sh` | Builds the core for device + simulator, makes the XCFramework, generates the Swift bindings |
| `FidoParole/NFCKey.swift` | `NFCTagReaderSession` → `NfcLink`; bridges CoreNFC's callbacks to the core's synchronous calls |
| `FidoParole/VaultModel.swift` | App state; runs key operations off the main actor |
| `FidoParole/Views/` | Start/unlock, vault list, entry editor, sheets (generator, backup, copy, delete) |

## Notes

- Hold the key to the top of the iPhone and keep it there until the system sheet
  says *Done*; reading and writing happen in the same tap.
- Over NFC the key has no power for a fingerprint sensor: use the PIN.
- Copied passwords are local-only (no Universal Clipboard) and expire after 30 s;
  the vault is covered in the app switcher and locks after 2 minutes away.
