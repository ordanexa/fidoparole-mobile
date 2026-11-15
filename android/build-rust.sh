#!/usr/bin/env bash
# Builds the Rust core for Android (arm64-v8a, armeabi-v7a, x86_64) and
# generates the Kotlin bindings. Called by Gradle (app:buildRust); can be run
# by hand:  ./build-rust.sh app/build [release|debug]
# Needs: rustup targets aarch64-linux-android armv7-linux-androideabi
# x86_64-linux-android, cargo-ndk (cargo install cargo-ndk), ANDROID_NDK_HOME.
set -euo pipefail
OUT="$(cd "$(dirname "${1:-app/build}")" && pwd)/$(basename "${1:-app/build}")"
PROFILE="${2:-release}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
FLAG=""; DIR=debug
if [[ "$PROFILE" == "release" ]]; then FLAG="--release"; DIR=release; fi
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o "$OUT/rustJniLibs" build -p fidoparole-ffi $FLAG
# Bindings come from the library's UniFFI metadata. Release builds are
# stripped, so read it from a host debug build (same API on every target).
cargo build -q -p fidoparole-ffi
HOSTLIB="target/debug/libfidoparole_ffi.so"
[[ -f "$HOSTLIB" ]] || HOSTLIB="target/debug/libfidoparole_ffi.dylib"
cargo run -q -p fidoparole-ffi --features cli --bin uniffi-bindgen -- generate \
  --library "$HOSTLIB" \
  --language kotlin --no-format --out-dir "$OUT/generated/uniffi"
