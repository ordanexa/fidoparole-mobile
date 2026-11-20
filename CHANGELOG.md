# Changelog

## 1.0.0 — 2026-11-20

First stable Ordanexa Android fork release; feature scope frozen.

- Read-only by default, with viewing, searching, password reveal/copy and encrypted backup export.
- Fresh phone biometric authentication for Edit, without requiring a token connection.
- When phone biometrics are unavailable, fresh authentication on the vault's token using PIN or the token's fingerprint over USB. NFC uses PIN.
- Edit ends after Save, Lock, backgrounding or USB detachment. Done returns to Read-only when there are no unsaved changes. NFC remains a session across individual taps.
- About / Info is available before and after unlocking and shows the installed version, usage guidance and project/license links.
- ARM64 and Universal release APKs; separate application ID from the official app, using the existing Ordanexa signing certificate for updates from test versions.

This release promotes the 0.1.2-test feature set. Changes for 1.0.0 are version and release documentation only. Maintenance covers bug/security fixes, Android compatibility and necessary upstream updates. New features require a separate decision.

Automated validation: 24 Rust tests and 11 Android tests passed in [build 44776876199](https://github.com/ordanexa/fidoparole-android-reader/actions/runs/44776876199). Both signed APKs were verified for package/version, architecture sets, signing certificate and 16 KiB ZIP alignment. Built source: `1accf2ec3583698f443e976b14edcbe2dfdde18a`. No new physical-device test was performed for this version-only promotion.

## 0.1.2-test

Added About / Info, installed-version display, usage help and project/license links.

## 0.1.1-test

Added fresh Edit authentication with a same-vault token fallback and parallel ARM64/Universal APK outputs.

## 0.1.0-test

Initial Android fork with Read-only default and explicit Edit mode.
