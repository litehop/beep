//! Pure `.BTF.ext` rewriting for build.rs. Lives in its own file so the
//! loader crate can `#[path]`-include it under `#[cfg(test)]` -- build
//! scripts have no test harness of their own.

use anyhow::{bail, ensure};

const BTF_MAGIC: u16 = 0xEB9F;
/// Header up to and including `line_info_len` (the pre-CO-RE v1 header).
const HDR_BASE_LEN: usize = 24;
/// Header including `core_relo_off`/`core_relo_len`.
const HDR_CORE_LEN: usize = 32;

fn u32_at(b: &[u8], off: usize) -> usize {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap()) as usize
}

fn put_u32(b: &mut [u8], off: usize, v: usize) {
    b[off..off + 4].copy_from_slice(&(v as u32).to_le_bytes());
}

/// Returns `ext` with the line_info subsection removed and func_info kept.
/// Fails if `ext` carries CO-RE relocations: the rewrite would silently drop
/// them and the loaded program would read wrong struct offsets.
pub fn strip_line_info(ext: &[u8]) -> anyhow::Result<Vec<u8>> {
    ensure!(
        ext.len() >= HDR_BASE_LEN,
        ".BTF.ext shorter than its header"
    );
    ensure!(
        u16::from_le_bytes([ext[0], ext[1]]) == BTF_MAGIC,
        ".BTF.ext has a bad magic"
    );
    let hdr_len = u32_at(ext, 4);
    ensure!(
        (HDR_BASE_LEN..=ext.len()).contains(&hdr_len),
        ".BTF.ext header length {hdr_len} out of range"
    );
    let (func_off, func_len) = (u32_at(ext, 8), u32_at(ext, 12));
    let has_core = hdr_len >= HDR_CORE_LEN;
    if has_core && u32_at(ext, 28) != 0 {
        bail!("CO-RE relocations present in .BTF.ext; the line_info strip would drop them");
    }
    let func_start = hdr_len + func_off;
    ensure!(
        func_start + func_len <= ext.len(),
        ".BTF.ext func_info out of bounds"
    );

    let mut out = ext[..hdr_len].to_vec();
    out.extend_from_slice(&ext[func_start..func_start + func_len]);
    put_u32(&mut out, 8, 0);
    put_u32(&mut out, 16, func_len);
    put_u32(&mut out, 20, 0);
    if has_core {
        put_u32(&mut out, 24, func_len);
        put_u32(&mut out, 28, 0);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FUNC: [u8; 12] = [8, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0];
    const LINE: [u8; 16] = [0xAA; 16];
    const CORE: [u8; 8] = [0xCC; 8];

    /// func_info | line_info | core_relo, header laid out like bpf-linker's.
    fn ext(hdr_len: usize, core: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&BTF_MAGIC.to_le_bytes());
        b.extend_from_slice(&[1, 0]);
        for v in [
            hdr_len,
            0,
            FUNC.len(),
            FUNC.len(),
            LINE.len(),
            FUNC.len() + LINE.len(),
            core.len(),
        ] {
            b.extend_from_slice(&(v as u32).to_le_bytes());
        }
        b.truncate(hdr_len);
        b.extend_from_slice(&FUNC);
        b.extend_from_slice(&LINE);
        b.extend_from_slice(core);
        b
    }

    #[test]
    fn keeps_func_info_because_the_kernel_needs_it_for_subprogs() {
        let out = strip_line_info(&ext(HDR_CORE_LEN, &[])).unwrap();
        assert_eq!(u32_at(&out, 8), 0);
        assert_eq!(u32_at(&out, 12), FUNC.len());
        assert_eq!(&out[HDR_CORE_LEN..], &FUNC, "func_info bytes must survive");
    }

    #[test]
    fn drops_line_info_and_leaves_consistent_offsets() {
        let out = strip_line_info(&ext(HDR_CORE_LEN, &[])).unwrap();
        assert_eq!(u32_at(&out, 20), 0, "line_info_len");
        assert_eq!(u32_at(&out, 28), 0, "core_relo_len");
        assert_eq!(out.len(), HDR_CORE_LEN + FUNC.len());
        assert!(!out.windows(LINE.len()).any(|w| w == LINE));
        assert_eq!(
            u32_at(&out, 16) + u32_at(&out, 24),
            2 * FUNC.len(),
            "line/core offsets must sit at the end of func_info, inside the blob"
        );
    }

    #[test]
    fn handles_pre_core_header() {
        let out = strip_line_info(&ext(HDR_BASE_LEN, &[])).unwrap();
        assert_eq!(out.len(), HDR_BASE_LEN + FUNC.len());
        assert_eq!(u32_at(&out, 20), 0);
    }

    #[test]
    fn rejects_core_relos_because_the_rewrite_would_silently_drop_them() {
        let err = strip_line_info(&ext(HDR_CORE_LEN, &CORE)).unwrap_err();
        assert!(err.to_string().contains("CO-RE"), "{err}");
    }

    #[test]
    fn rejects_truncated_input() {
        let mut b = ext(HDR_CORE_LEN, &[]);
        b.truncate(HDR_CORE_LEN + FUNC.len() - 1);
        assert!(strip_line_info(&b).is_err());
        assert!(strip_line_info(&b[..8]).is_err());
    }
}
