fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-arg-bins={dir}/kf.bc");
    println!("cargo:rerun-if-changed=kf.bc");
}
