use anyhow::{Context, Result, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroize;

use crate::crypto::MASTER_KEY_LEN;
use crate::format::Argon2Meta;

pub const DEFAULT_MEM_KIB: u32 = 256 * 1024;
pub const DEFAULT_ITERATIONS: u32 = 3;
pub const DEFAULT_PARALLELISM: u32 = 1;

/// Resolve user-supplied Argon2 overrides against the project defaults and
/// validate the result. `None` for any field means "use the default"; a
/// `Some(0)` is a typo and is rejected with a clear per-field error.
pub fn resolve_argon2_params(
    mem_kib: Option<u32>,
    iterations: Option<u32>,
    parallelism: Option<u32>,
) -> Result<(u32, u32, u32)> {
    let mem_kib = mem_kib.unwrap_or(DEFAULT_MEM_KIB);
    let iterations = iterations.unwrap_or(DEFAULT_ITERATIONS);
    let parallelism = parallelism.unwrap_or(DEFAULT_PARALLELISM);
    if mem_kib == 0 {
        bail!("--argon2-mem must be at least 1 KiB");
    }
    if iterations == 0 {
        bail!("--argon2-iters must be at least 1");
    }
    if parallelism == 0 {
        bail!("--argon2-lanes must be at least 1");
    }
    Ok((mem_kib, iterations, parallelism))
}

pub fn derive_key_from_password(
    password: &[u8],
    meta: &Argon2Meta,
) -> Result<[u8; MASTER_KEY_LEN]> {
    let params = Params::new(
        meta.mem_kib,
        meta.iterations,
        meta.parallelism,
        Some(MASTER_KEY_LEN),
    )
    .map_err(|e| anyhow::anyhow!("invalid Argon2 params: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; MASTER_KEY_LEN];
    argon
        .hash_password_into(password, &meta.salt, &mut out)
        .map_err(|e| anyhow::anyhow!("argon2id failed: {e}"))?;
    Ok(out)
}

pub fn read_password(prompt: &str, confirm: bool) -> Result<Vec<u8>> {
    if let Ok(p) = std::env::var("ASYMCRYPT_PASSWORD") {
        let mut s = p;
        let bytes = s.as_bytes().to_vec();
        s.zeroize();
        if bytes.is_empty() {
            bail!("ASYMCRYPT_PASSWORD is empty");
        }
        return Ok(bytes);
    }
    let mut pw = rpassword::prompt_password(prompt).context("reading password")?;
    if pw.is_empty() {
        pw.zeroize();
        bail!("empty password");
    }
    if confirm {
        let mut again = rpassword::prompt_password("Confirm password: ")
            .context("reading password confirmation")?;
        let matches = again == pw;
        again.zeroize();
        if !matches {
            pw.zeroize();
            bail!("passwords do not match");
        }
    }
    let bytes = pw.as_bytes().to_vec();
    pw.zeroize();
    Ok(bytes)
}

pub fn random_salt() -> Result<[u8; 16]> {
    let mut s = [0u8; 16];
    getrandom::fill(&mut s).context("getrandom failed")?;
    Ok(s)
}
