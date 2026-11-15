// Generates the Kotlin and Swift bindings:
//   cargo run -p fidoparole-ffi --features cli --bin uniffi-bindgen -- generate \
//     --library <path to libfidoparole_ffi.so/.dylib/.a> --language kotlin|swift --out-dir <dir>
fn main() {
    uniffi::uniffi_bindgen_main()
}
