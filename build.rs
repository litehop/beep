//! Cross-builds the `beep-ebpf` program crate for `bpfel-unknown-none`
//! (via nightly + bpf-linker, see .cargo/config.toml) and embeds the
//! resulting object at OUT_DIR/beep-ebpf for `aya::include_bytes_aligned!`
//! in src/lib.rs.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context as _};

#[path = "build_support/btf_ext.rs"]
mod btf_ext;

fn main() -> aya_build::Result<()> {
    // aya-build only watches `ebpf/`; the object also embeds `beep-common`.
    println!("cargo:rerun-if-changed=common");
    println!("cargo:rerun-if-changed=Cargo.lock");
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
/// only ships what aya actually reads back. `.rel.BTF`/`.rel.BTF.ext` are
/// linker-only relocation sections that aya never reads, so they go too.
fn strip_dwarf_keep_btf(object: &Path) -> aya_build::Result<()> {
    let objcopy = locate_llvm_objcopy()?;
    let status = Command::new(&objcopy)
        .arg("--strip-debug")
        .arg("--remove-section=.rel.BTF")
        .arg("--remove-section=.rel.BTF.ext")
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
    if env::var("PROFILE").as_deref() == Ok("release") {
        strip_line_info(&objcopy, object)?;
    }
    Ok(())
}

/// Release objects drop `.BTF.ext` line_info (source-line annotations in
/// verifier logs and bpftool dumps); func_info stays because the kernel needs
/// it for subprogs. Dev builds keep line_info for debugging verifier
/// rejections.
fn strip_line_info(objcopy: &Path, object: &Path) -> aya_build::Result<()> {
    let ext_path = object.with_extension("btf.ext");
    objcopy_run(
        objcopy,
        &format!("--dump-section=.BTF.ext={}", ext_path.display()),
        object,
    )?;
    let ext = std::fs::read(&ext_path).context("reading dumped .BTF.ext")?;
    std::fs::write(&ext_path, btf_ext::strip_line_info(&ext)?)
        .context("writing rewritten .BTF.ext")?;
    objcopy_run(
        objcopy,
        &format!("--update-section=.BTF.ext={}", ext_path.display()),
        object,
    )
}

fn objcopy_run(objcopy: &Path, flag: &str, object: &Path) -> aya_build::Result<()> {
    let status = Command::new(objcopy)
        .arg(flag)
        .arg(object)
        .status()
        .with_context(|| format!("running {} {flag}", objcopy.display()))?;
    if !status.success() {
        bail!("{} {flag} exited with {status}", objcopy.display());
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
