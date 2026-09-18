//! Cross-builds the `beep-ebpf` program crate for `bpfel-unknown-none`
//! (via nightly + bpf-linker, see .cargo/config.toml) and embeds the
//! resulting object at OUT_DIR/beep-ebpf for `aya::include_bytes_aligned!`
//! in src/lib.rs.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context as _};

fn main() -> aya_build::Result<()> {
    aya_build::build_ebpf(
        [aya_build::Package {
            name: "beep-ebpf",
            root_dir: "ebpf",
            ..Default::default()
        }],
        aya_build::Toolchain::default(),
    )?;
    strip_dwarf_keep_btf(&ebpf_object_path()?)
}

fn ebpf_object_path() -> aya_build::Result<PathBuf> {
    let out_dir = env::var_os("OUT_DIR").context("OUT_DIR not set by cargo")?;
    Ok(Path::new(&out_dir).join("beep-ebpf"))
}

/// `[profile.release.package.beep-ebpf]`'s `debug = 2` (Cargo.toml) is what
/// makes bpf-linker emit `.BTF`/`.BTF.ext`, which aya needs at load time for
/// map + relocation info -- but the DWARF `.debug_*` sections that come
/// along with it serve no runtime purpose and dominate the embedded
/// object's size. Strip them here, after linking, so the loader binary
/// only ships what aya actually reads back.
fn strip_dwarf_keep_btf(object: &Path) -> aya_build::Result<()> {
    let objcopy = locate_llvm_objcopy()?;
    let status = Command::new(&objcopy)
        .arg("--strip-debug")
        .arg(object)
        .status()
        .with_context(|| {
            format!(
                "running {} --strip-debug {}",
                objcopy.display(),
                object.display()
            )
        })?;
    if !status.success() {
        bail!(
            "{} --strip-debug {} exited with {status}",
            objcopy.display(),
            object.display()
        );
    }
    Ok(())
}

/// Prefers whatever `llvm-objcopy` is already on `PATH` (e.g. the VM's
/// apt-installed llvm package), falling back to the active rustc
/// toolchain's own `llvm-tools` component -- declared in
/// rust-toolchain.toml so both dev machines and CI have it without an
/// extra manual install step.
fn locate_llvm_objcopy() -> aya_build::Result<PathBuf> {
    if Command::new("llvm-objcopy")
        .arg("--version")
        .output()
        .is_ok()
    {
        return Ok(PathBuf::from("llvm-objcopy"));
    }

    let sysroot = Command::new("rustc")
        .args(["--print", "sysroot"])
        .output()
        .context("running `rustc --print sysroot`")?
        .stdout;
    let sysroot =
        String::from_utf8(sysroot).context("`rustc --print sysroot` output was not UTF-8")?;
    let host = env::var("HOST").context("HOST not set by cargo")?;
    let candidate = Path::new(sysroot.trim())
        .join("lib/rustlib")
        .join(host)
        .join("bin/llvm-objcopy");
    if candidate.exists() {
        Ok(candidate)
    } else {
        bail!(
            "llvm-objcopy not found on PATH or at {} -- install the `llvm-tools` rustup component",
            candidate.display()
        );
    }
}
