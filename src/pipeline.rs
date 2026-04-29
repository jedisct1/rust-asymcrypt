use anyhow::{Context, Result, anyhow, bail};
use std::io::{Read, Write};
use std::path::Path;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::cli::{DecryptArgs, EncryptArgs, InitArgs, validate_chunk_size};
use crate::crypto::{
    self, CIPHER_KEY_LEN, FILE_NONCE_LEN, KEY_CHECK_LEN, MASTER_KEY_LEN, NONCE_LEN, TAG_LEN,
};
use crate::format::{
    self, Argon2Meta, FINAL_CHUNK_FLAG, Header, decode_chunk_framing, encode_chunk_framing,
    new_chunk_ad, update_chunk_ad,
};
use crate::io::{Input, Output, parent_or_cwd, read_full};
use crate::key::{
    self, KeyFileFormat, KeyKind, KeyLock, KeyRole, check_key_permissions, parse_key_file,
    random_key, stage_key_replacement,
};
use crate::password::{
    derive_key_from_password, random_salt, read_password, resolve_argon2_params,
};

pub fn run_init(args: InitArgs) -> Result<()> {
    if args.password && args.recovery_out.is_some() {
        bail!(
            "--recovery-out cannot be used with --password (the password is the recovery secret)"
        );
    }
    if !args.password && args.recovery_out.is_none() {
        bail!("--recovery-out is required without --password");
    }
    if !args.password
        && (args.argon2_mem.is_some() || args.argon2_iters.is_some() || args.argon2_lanes.is_some())
    {
        bail!("--argon2-mem, --argon2-iters, and --argon2-lanes require --password");
    }

    let format = if args.hex {
        KeyFileFormat::Hex
    } else {
        KeyFileFormat::Raw
    };

    validate_init_path(&args.out, "current key")?;
    if let Some(rp) = args.recovery_out.as_deref() {
        validate_init_path(rp, "recovery key")?;
        if paths_equal(&args.out, rp)? {
            bail!(
                "current and recovery output paths must differ ({} == {})",
                args.out.display(),
                rp.display()
            );
        }
    }

    let kdf = if args.password {
        let (mem_kib, iterations, parallelism) =
            resolve_argon2_params(args.argon2_mem, args.argon2_iters, args.argon2_lanes)?;
        Some(Argon2Meta {
            salt: random_salt()?,
            mem_kib,
            iterations,
            parallelism,
        })
    } else {
        None
    };

    let k0: Zeroizing<[u8; MASTER_KEY_LEN]> = if let Some(meta) = kdf.as_ref() {
        let password = Zeroizing::new(read_password("Password: ", true)?);
        Zeroizing::new(derive_key_from_password(&password, meta)?)
    } else {
        Zeroizing::new(random_key()?)
    };

    let mut k1: Zeroizing<[u8; MASTER_KEY_LEN]> = Zeroizing::new(*k0);
    crypto::evolve_key(&mut k1);

    let current_bytes = Zeroizing::new(key::encode_key_file(
        &k1,
        KeyKind::chain_from_kdf(kdf.as_ref()),
        format,
    ));

    let mut persisted: Vec<std::path::PathBuf> = Vec::new();

    if let Some(rp) = args.recovery_out.as_deref() {
        let recovery_bytes =
            Zeroizing::new(key::encode_key_file(&k0, KeyKind::PlainRecovery, format));
        match key::write_new_file_durable(rp, &recovery_bytes, Some(0o600)) {
            Ok(outcome) => {
                persisted.push(rp.to_path_buf());
                outcome.warn("recovery key written");
            }
            Err(e) => return Err(e.context(format!("writing recovery key {}", rp.display()))),
        }
    }

    match key::write_new_file_durable(&args.out, &current_bytes, Some(0o600)) {
        Ok(outcome) => {
            outcome.warn("current key written");
            Ok(())
        }
        Err(e) => {
            for path in &persisted {
                if let Err(unlink_err) = std::fs::remove_file(path)
                    && unlink_err.kind() != std::io::ErrorKind::NotFound
                {
                    eprintln!(
                        "asymcrypt: warning: failed to clean up {} after init failure: {}",
                        path.display(),
                        unlink_err
                    );
                }
            }
            Err(e.context(format!("writing current key {}", args.out.display())))
        }
    }
}

fn validate_init_path(path: &Path, label: &str) -> Result<()> {
    let parent = parent_or_cwd(path);
    let parent_meta = std::fs::symlink_metadata(parent).with_context(|| {
        format!(
            "{} parent directory {} does not exist or is unreadable",
            label,
            parent.display()
        )
    })?;
    if !parent_meta.is_dir() {
        bail!("{} parent {} is not a directory", label, parent.display());
    }
    Ok(())
}

fn paths_equal(a: &Path, b: &Path) -> Result<bool> {
    Ok(std::path::absolute(a)? == std::path::absolute(b)?)
}

pub fn run_encrypt(args: EncryptArgs) -> Result<()> {
    validate_chunk_size(args.chunk_size)?;
    let _lock = KeyLock::acquire(&args.key_file)?;

    let mode = check_key_permissions(&args.key_file, args.insecure_perms)?;
    let key_bytes_raw = std::fs::read(&args.key_file)
        .with_context(|| format!("reading {}", args.key_file.display()))?;
    let parsed = parse_key_file(&key_bytes_raw)?;
    if parsed.role == KeyRole::Recovery {
        bail!(
            "key file {} is a recovery key (offline-only); use the on-device chain key for encryption",
            args.key_file.display()
        );
    }
    let key_format = parsed.format;
    let kdf = parsed.kdf;
    let stream_key = Zeroizing::new(parsed.key);
    drop(key_bytes_raw);

    let mut input = Input::open(args.input.as_deref())?;
    let mut output = Output::open(args.output.as_deref(), args.force)?;

    // Pre-rotation: commit `K_{n+1}` to the key file *before* producing any
    // ciphertext. After this point the on-disk key is `K_{n+1}` and only
    // this process holds `K_n` in memory, so a mid-stream crash leaves any
    // partial output undecryptable from the device's key file. Cost: every
    // encryption attempt that reaches this point burns a chain step even on
    // failure, which `--max-key-steps` must absorb.
    let mut next_key = Zeroizing::new(*stream_key);
    crypto::evolve_key(&mut next_key);
    let staged = stage_key_replacement(
        &args.key_file,
        &next_key,
        KeyKind::chain_from_kdf(kdf.as_ref()),
        key_format,
        Some(mode),
    )
    .context("staging next key")?;
    drop(next_key);
    let key_outcome = staged.commit().context("rotating key file")?;
    key_outcome.warn("key rotated");

    let mut file_nonce = [0u8; FILE_NONCE_LEN];
    getrandom::fill(&mut file_nonce).context("getrandom failed")?;

    let header = Header {
        chunk_size: args.chunk_size,
        file_nonce,
        kdf,
    };
    let header_bytes = header.encode();
    output.write_all(&header_bytes).context("writing header")?;
    output
        .write_all(&crypto::key_check(&stream_key, &file_nonce))
        .context("writing key-check record")?;

    let (file_key, base_nonce) = crypto::derive_file_secrets(&stream_key, &file_nonce);
    let file_key = Zeroizing::new(file_key);
    let base_nonce = Zeroizing::new(base_nonce);
    drop(stream_key);

    let mut ctx = ChunkContext::new(&file_key, &base_nonce, &header_bytes);
    encrypt_chunks(&mut input, &mut output, &mut ctx, args.chunk_size as usize)?;

    let output_outcome = output.commit().context("committing output")?;
    output_outcome.warn("output committed");
    Ok(())
}

fn next_chunk_index(i: u64) -> Result<u64> {
    i.checked_add(1)
        .ok_or_else(|| anyhow!("chunk_index overflow"))
}

/// Loop-invariant per-stream context: the per-file AEGIS key, the
/// per-file base nonce, and a reusable AD buffer pre-loaded with the
/// header bytes — only the trailing 13 bytes are rewritten per chunk
/// via [`update_chunk_ad`].
struct ChunkContext<'a> {
    file_key: &'a [u8; CIPHER_KEY_LEN],
    base_nonce: &'a [u8; NONCE_LEN],
    header_len: usize,
    ad: Vec<u8>,
}

impl<'a> ChunkContext<'a> {
    fn new(
        file_key: &'a [u8; CIPHER_KEY_LEN],
        base_nonce: &'a [u8; NONCE_LEN],
        header_bytes: &[u8],
    ) -> Self {
        Self {
            file_key,
            base_nonce,
            header_len: header_bytes.len(),
            ad: new_chunk_ad(header_bytes),
        }
    }
}

fn encrypt_chunks(
    input: &mut Input,
    output: &mut Output,
    ctx: &mut ChunkContext<'_>,
    chunk_size: usize,
) -> Result<()> {
    let mut current = vec![0u8; chunk_size];
    let mut next = vec![0u8; chunk_size];
    let mut chunk_index: u64 = 0;

    let mut current_len = read_full(input, &mut current).context("reading input")?;
    let mut current_is_last = current_len < chunk_size;

    loop {
        if current_is_last {
            emit_chunk_in_place(output, ctx, chunk_index, &mut current[..current_len], true)?;
            return Ok(());
        }
        let next_len = read_full(input, &mut next).context("reading input")?;
        let next_is_last = next_len < chunk_size;
        emit_chunk_in_place(output, ctx, chunk_index, &mut current[..chunk_size], false)?;
        chunk_index = next_chunk_index(chunk_index)?;
        std::mem::swap(&mut current, &mut next);
        current_len = next_len;
        current_is_last = next_is_last;
    }
}

fn emit_chunk_in_place(
    output: &mut Output,
    ctx: &mut ChunkContext<'_>,
    chunk_index: u64,
    buf: &mut [u8],
    is_final: bool,
) -> Result<()> {
    let flags = if is_final { FINAL_CHUNK_FLAG } else { 0 };
    let plain_len: u32 = buf
        .len()
        .try_into()
        .map_err(|_| anyhow!("chunk plaintext too large"))?;
    update_chunk_ad(&mut ctx.ad, ctx.header_len, chunk_index, plain_len, flags);
    let nonce = crypto::derive_chunk_nonce(ctx.base_nonce, chunk_index);
    let tag = crypto::encrypt_chunk_in_place(ctx.file_key, &nonce, buf, &ctx.ad);
    output
        .write_all(&encode_chunk_framing(plain_len, flags))
        .context("writing chunk framing")?;
    output.write_all(buf).context("writing chunk ciphertext")?;
    output.write_all(&tag).context("writing chunk tag")?;
    Ok(())
}

pub fn run_decrypt(args: DecryptArgs) -> Result<()> {
    // Validate the key source before opening the input so a stdin read
    // never blocks waiting on header bytes for a request that will be
    // rejected by the role check.
    let prevalidated_key: Option<Zeroizing<[u8; MASTER_KEY_LEN]>> = if args.password {
        if args.key_file.is_some() {
            bail!("either --key-file or --password is required, not both");
        }
        None
    } else {
        let path: &Path = args
            .key_file
            .as_deref()
            .ok_or_else(|| anyhow!("either --key-file or --password is required"))?;
        let _ = check_key_permissions(path, args.insecure_perms)?;
        let raw = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let parsed = parse_key_file(&raw)?;
        if parsed.role != KeyRole::Recovery {
            bail!(
                "key file {} is an on-device chain key, not a recovery key; use the offline recovery key, or pass --password",
                path.display()
            );
        }
        Some(Zeroizing::new(parsed.key))
    };

    let mut input = Input::open(args.input.as_deref())?;
    let (header, header_bytes) = Header::read(&mut input)?;

    let candidate_key: Zeroizing<[u8; MASTER_KEY_LEN]> = if let Some(k) = prevalidated_key {
        k
    } else {
        let kdf = header
            .kdf
            .as_ref()
            .ok_or_else(|| anyhow!("file has no embedded password KDF metadata"))?;
        let mut password = read_password("Password: ", false)?;
        let key = derive_key_from_password(&password, kdf)?;
        password.zeroize();
        Zeroizing::new(key)
    };

    let mut stored_check = [0u8; KEY_CHECK_LEN];
    input
        .read_exact(&mut stored_check)
        .context("reading key-check record")?;

    let candidate_key = find_chain_step(
        candidate_key,
        &header.file_nonce,
        &stored_check,
        args.max_key_steps,
    )?;

    let (file_key, base_nonce) = crypto::derive_file_secrets(&candidate_key, &header.file_nonce);
    let file_key = Zeroizing::new(file_key);
    let base_nonce = Zeroizing::new(base_nonce);
    drop(candidate_key);

    let mut output = Output::open(args.output.as_deref(), args.force)?;
    let mut ctx = ChunkContext::new(&file_key, &base_nonce, &header_bytes);
    decrypt_chunks(
        &mut input,
        &mut output,
        &mut ctx,
        header.chunk_size as usize,
    )?;

    let outcome = output.commit().context("committing decrypted output")?;
    outcome.warn("plaintext committed");
    Ok(())
}

fn find_chain_step(
    mut candidate_key: Zeroizing<[u8; MASTER_KEY_LEN]>,
    file_nonce: &[u8; FILE_NONCE_LEN],
    stored_check: &[u8; KEY_CHECK_LEN],
    max_steps: u64,
) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>> {
    use std::io::IsTerminal;
    let stderr_is_tty = std::io::stderr().is_terminal();
    let mut steps: u64 = 0;
    loop {
        if crypto::key_check(&candidate_key, file_nonce)
            .ct_eq(stored_check)
            .into()
        {
            break;
        }
        if steps >= max_steps {
            bail!(
                "key check did not match within {} step(s); wrong key or password?",
                max_steps
            );
        }
        crypto::evolve_key(&mut candidate_key);
        steps += 1;
        if stderr_is_tty && steps.is_multiple_of(1024) {
            eprint!("\rsearching key chain: {steps} steps");
            let _ = std::io::Write::flush(&mut std::io::stderr());
        }
    }
    if stderr_is_tty && steps >= 1024 {
        eprintln!("\rkey chain matched at step {steps}              ");
    } else if steps > 0 {
        eprintln!("asymcrypt: matched chain step {steps}");
    }
    Ok(candidate_key)
}

fn decrypt_chunks(
    input: &mut Input,
    output: &mut Output,
    ctx: &mut ChunkContext<'_>,
    chunk_size: usize,
) -> Result<()> {
    let mut buf = vec![0u8; chunk_size];
    let mut chunk_index: u64 = 0;

    loop {
        let mut framing = [0u8; format::CHUNK_FRAMING_LEN];
        input
            .read_exact(&mut framing)
            .context("reading chunk framing")?;
        let (plain_len_u32, flags) = decode_chunk_framing(&framing);
        let is_final = format::validate_chunk_flags(flags)?;
        let plain_len = plain_len_u32 as usize;
        if plain_len > chunk_size {
            bail!(
                "chunk {} plain_len {} exceeds chunk_size {}",
                chunk_index,
                plain_len,
                chunk_size
            );
        }
        if !is_final && plain_len != chunk_size {
            bail!(
                "non-final chunk {} has length {} (expected {})",
                chunk_index,
                plain_len,
                chunk_size
            );
        }
        input
            .read_exact(&mut buf[..plain_len])
            .context("reading chunk ciphertext")?;
        let mut tag = [0u8; TAG_LEN];
        input.read_exact(&mut tag).context("reading chunk tag")?;
        let nonce = crypto::derive_chunk_nonce(ctx.base_nonce, chunk_index);
        update_chunk_ad(
            &mut ctx.ad,
            ctx.header_len,
            chunk_index,
            plain_len_u32,
            flags,
        );
        crypto::decrypt_chunk_in_place(ctx.file_key, &nonce, &mut buf[..plain_len], &tag, &ctx.ad)
            .map_err(|_| anyhow!("authentication failed for chunk {}", chunk_index))?;
        output
            .write_all(&buf[..plain_len])
            .context("writing decrypted chunk")?;
        chunk_index = next_chunk_index(chunk_index)?;
        if is_final {
            let mut probe = [0u8; 1];
            let extra = input
                .read(&mut probe)
                .context("checking for trailing data")?;
            if extra != 0 {
                bail!("trailing bytes after final chunk");
            }
            return Ok(());
        }
    }
}
