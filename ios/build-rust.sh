#!/usr/bin/env bash
# Builds the Rust core for iOS (device + simulator) as an XCFramework and
# generates the Swift bindings. Run on macOS with Xcode and rustup:
#   rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
#   ./build-rust.sh            # release (default) or: ./build-rust.sh debug
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
PROFILE="${1:-release}"
FLAG=""; DIR=debug
if [[ "$PROFILE" == "release" ]]; then FLAG="--release"; DIR=release; fi
cd "$ROOT"
for T in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do
  cargo build -p fidoparole-ffi $FLAG --target "$T"
done

# Swift bindings from the host build's UniFFI metadata (release builds are stripped).
cargo build -q -p fidoparole-ffi
GEN="$HERE/Generated"
rm -rf "$GEN" && mkdir -p "$GEN"
cargo run -q -p fidoparole-ffi --features cli --bin uniffi-bindgen -- generate \
  --library target/debug/libfidoparole_ffi.dylib --language swift --no-format --out-dir "$GEN"

# Headers for the XCFramework: the C header + a module map named module.modulemap.
HDR="$ROOT/target/ios-headers"
rm -rf "$HDR" && mkdir -p "$HDR"
mv "$GEN/fidoparole_ffiFFI.h" "$HDR/"
mv "$GEN/fidoparole_ffiFFI.modulemap" "$HDR/module.modulemap"

SIM="$ROOT/target/ios-sim-universal/$DIR"
mkdir -p "$SIM"
lipo -create \
  "target/aarch64-apple-ios-sim/$DIR/libfidoparole_ffi.a" \
  "target/x86_64-apple-ios/$DIR/libfidoparole_ffi.a" \
  -output "$SIM/libfidoparole_ffi.a"

OUT="$HERE/Frameworks/FidoParoleFFI.xcframework"
rm -rf "$OUT" && mkdir -p "$HERE/Frameworks"
xcodebuild -create-xcframework \
  -library "target/aarch64-apple-ios/$DIR/libfidoparole_ffi.a" -headers "$HDR" \
  -library "$SIM/libfidoparole_ffi.a" -headers "$HDR" \
  -output "$OUT"
echo "Built $OUT and $GEN/fidoparole_ffi.swift"
