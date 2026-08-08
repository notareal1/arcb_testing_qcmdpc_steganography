// build.rs
fn main() {
    // C reference decoder removed — using pure Rust implementation
    println!("cargo:rerun-if-changed=build.rs");
}
