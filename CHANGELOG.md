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

## 0.1.2-test

Added About / Info, installed-version display, usage help and project/license links.

## 0.1.1-test

Added fresh Edit authentication with a same-vault token fallback and parallel ARM64/Universal APK outputs.

## 0.1.0-test

Initial Android fork with Read-only default and explicit Edit mode.
