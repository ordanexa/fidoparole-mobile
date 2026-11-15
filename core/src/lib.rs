//! FidoParole core, shared by the desktop, Android and iOS apps.
//!
//! * [`vault`]: the vault data model, the on-key blob format (hmac-secret →
//!   HKDF → AES-256-GCM over deflated JSON) and passphrase backup files.
//! * [`ctap`]: a CTAP2 client in pure Rust — CTAPHID and NFC framing over a
//!   transport the platform provides, PIN/UV auth protocols 1 and 2,
//!   makeCredential / getAssertion with hmac-secret, largeBlobKey and
//!   credProtect, largeBlobs and credential management.
//! * [`keyops`]: the vault operations (create, unlock, save, delete) on top of
//!   the CTAP client.

pub mod ctap;
pub mod keyops;
pub mod vault;
