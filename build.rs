//! Cross-builds the `servicelb-ebpf` program crate for `bpfel-unknown-none`
//! (via nightly + bpf-linker, see ../.cargo/config.toml) and embeds the
//! resulting object at OUT_DIR/servicelb-ebpf for `aya::include_bytes_aligned!`
//! in src/main.rs.

fn main() -> aya_build::Result<()> {
    aya_build::build_ebpf(
        [aya_build::Package {
            name: "u7s-servicelb-ebpf",
            root_dir: "servicelb-ebpf",
            ..Default::default()
        }],
        aya_build::Toolchain::default(),
    )
}
