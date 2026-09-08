//! Cross-builds the `beep-ebpf` program crate for `bpfel-unknown-none`
//! (via nightly + bpf-linker, see .cargo/config.toml) and embeds the
//! resulting object at OUT_DIR/beep-ebpf for `aya::include_bytes_aligned!`
//! in src/main.rs.

fn main() -> aya_build::Result<()> {
    aya_build::build_ebpf(
        [aya_build::Package {
            name: "beep-ebpf",
            root_dir: "ebpf",
            ..Default::default()
        }],
        aya_build::Toolchain::default(),
    )
}
