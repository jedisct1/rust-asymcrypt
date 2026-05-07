use anyhow::{Context, Result, anyhow, bail};
use std::io::{Read, Write};
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

use crate::cli::{DecryptArgs, EncryptArgs, InitArgs, validate_chunk_size};
use crate::crypto::{
    self, CIPHER_KEY_LEN, DK_SEED_LEN, FILE_NONCE_LEN, NONCE_LEN, SHARED_SECRET_LEN, TAG_LEN,
};
use crate::format::{
    self, Argon2Meta, FINAL_CHUNK_FLAG, Header, PasswordBlob, decode_chunk_framing,
    encode_chunk_framing, new_chunk_ad, update_chunk_ad,
};
use crate::io::{Input, Output, parent_or_cwd, read_full};
use crate::key::{
    self, KeyFileFormat, ParsedKeyFile, check_key_permissions, encode_composite_file,
    encode_dk_seed_file, encode_ek_file, parse_key_file,
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

    validate_init_path(&args.out, "device key")?;
    if let Some(rp) = args.recovery_out.as_deref() {
        validate_init_path(rp, "recovery key")?;
        if paths_equal(&args.out, rp)? {
            bail!(
                "device and recovery output paths must differ ({} == {})",
                args.out.display(),
                rp.display()
            );
        }
    }

    if args.password {
        let (mem_kib, iterations, parallelism) =
            resolve_argon2_params(args.argon2_mem, args.argon2_iters, args.argon2_lanes)?;
        let meta = Argon2Meta {
            salt: random_salt()?,
            mem_kib,
            iterations,
            parallelism,
        };

        let password = Zeroizing::new(read_password("Password: ", true)?);
        let mut argon2_key = Zeroizing::new(derive_key_from_password(&password, &meta)?);
        drop(password);

        let (seed, ek_bytes) = crypto::kem_generate();
        let mut seed = Zeroizing::new(seed);

        let (encrypted_seed, seed_tag) = crypto::wrap_dk_seed(&argon2_key, &seed);
        seed.zeroize();
        argon2_key.zeroize();

        let blob = Zeroizing::new(
            PasswordBlob {
                encrypted_seed,
                seed_tag,
                argon2: meta,
            }
            .encode(),
        );

        let file_bytes = Zeroizing::new(encode_composite_file(&ek_bytes, &blob, format));
        match key::write_new_file_durable(&args.out, &file_bytes, Some(0o600)) {
            Ok(outcome) => {
                outcome.warn("device key written");
                Ok(())
            }
            Err(e) => Err(e.context(format!("writing device key {}", args.out.display()))),
        }
    } else {
        let (seed, ek_bytes) = crypto::kem_generate();
        let seed = Zeroizing::new(seed);

        let mut persisted: Vec<std::path::PathBuf> = Vec::new();

        if let Some(rp) = args.recovery_out.as_deref() {
            let recovery_bytes = Zeroizing::new(encode_dk_seed_file(&seed, format));
            match key::write_new_file_durable(rp, &recovery_bytes, Some(0o600)) {
                Ok(outcome) => {
                    persisted.push(rp.to_path_buf());
                    outcome.warn("recovery key written");
                }
                Err(e) => return Err(e.context(format!("writing recovery key {}", rp.display()))),
            }
        }

        let ek_file_bytes = encode_ek_file(&ek_bytes, format);
        match key::write_new_file_durable(&args.out, &ek_file_bytes, Some(0o644)) {
            Ok(outcome) => {
                outcome.warn("device key written");
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
                Err(e.context(format!("writing device key {}", args.out.display())))
            }
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

    let mut key_bytes_raw = std::fs::read(&args.key_file)
        .with_context(|| format!("reading {}", args.key_file.display()))?;
    let parsed = parse_key_file(&key_bytes_raw)?;
    key_bytes_raw.zeroize();

    let (ek_bytes, password_blob_bytes) = match &parsed {
        ParsedKeyFile::EncapsulationKey { ek_bytes, .. } => (*ek_bytes, None),
        ParsedKeyFile::Composite {
            ek_bytes,
            password_blob,
            ..
        } => {
            check_key_permissions(&args.key_file, args.insecure_perms)?;
            (*ek_bytes, Some(password_blob.clone()))
        }
        ParsedKeyFile::DecapsulationSeed { .. } => {
            bail!(
                "key file {} is a decapsulation seed (recovery-only); use the device encapsulation key for encryption",
                args.key_file.display()
            );
        }
    };

    let mut input = Input::open(args.input.as_deref())?;
    let mut output = Output::open(args.output.as_deref(), args.force)?;

    let (kem_ct, shared_secret) = crypto::kem_encapsulate(&ek_bytes)?;
    let shared_secret = Zeroizing::new(shared_secret);

    let mut file_nonce = [0u8; FILE_NONCE_LEN];
    getrandom::fill(&mut file_nonce).context("getrandom failed")?;

    let password_blob = if let Some(blob_bytes) = password_blob_bytes {
        Some(PasswordBlob::decode(&blob_bytes)?)
    } else {
        None
    };

    let header = Header {
        chunk_size: args.chunk_size,
        file_nonce,
        kem_ciphertext: kem_ct,
        password_blob,
    };
    let header_bytes = header.encode();
    output.write_all(&header_bytes).context("writing header")?;

    let (file_key, base_nonce) = crypto::derive_file_secrets(&shared_secret, &file_nonce);
    let file_key = Zeroizing::new(file_key);
    let base_nonce = Zeroizing::new(base_nonce);
    drop(shared_secret);

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
    let prevalidated_seed: Option<Zeroizing<[u8; DK_SEED_LEN]>> = if args.password {
        if args.key_file.is_some() {
            bail!("either --key-file or --password is required, not both");
        }
        None
    } else {
        let path: &Path = args
            .key_file
            .as_deref()
            .ok_or_else(|| anyhow!("either --key-file or --password is required"))?;
        let raw = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let parsed = parse_key_file(&raw)?;
        match parsed {
            ParsedKeyFile::DecapsulationSeed { seed, .. } => {
                check_key_permissions(path, args.insecure_perms)?;
                Some(Zeroizing::new(seed))
            }
            ParsedKeyFile::EncapsulationKey { .. } => {
                bail!(
                    "key file {} is a public encapsulation key, not a decapsulation seed; use the offline recovery key, or pass --password",
                    path.display()
                );
            }
            ParsedKeyFile::Composite { .. } => {
                bail!(
                    "key file {} is a composite (password-mode) key; use --password to decrypt, or pass the offline recovery key",
                    path.display()
                );
            }
        }
    };

    let mut input = Input::open(args.input.as_deref())?;
    let (header, header_bytes) = Header::read(&mut input)?;

    let shared_secret: Zeroizing<[u8; SHARED_SECRET_LEN]> = if let Some(seed) = prevalidated_seed {
        Zeroizing::new(crypto::kem_decapsulate(&seed, &header.kem_ciphertext))
    } else {
        let blob = header.password_blob.as_ref().ok_or_else(|| {
            anyhow!(
                "this file was not encrypted in password mode; use --key-file with a recovery key"
            )
        })?;

        let mut password = read_password("Password: ", false)?;
        let argon2_key = Zeroizing::new(derive_key_from_password(&password, &blob.argon2)?);
        password.zeroize();

        let mut seed = Zeroizing::new(
            crypto::unwrap_dk_seed(&argon2_key, &blob.encrypted_seed, &blob.seed_tag)
                .map_err(|_| anyhow!("wrong password"))?,
        );
        drop(argon2_key);

        let ss = Zeroizing::new(crypto::kem_decapsulate(&seed, &header.kem_ciphertext));
        seed.zeroize();
        ss
    };

    let (file_key, base_nonce) = crypto::derive_file_secrets(&shared_secret, &header.file_nonce);
    let file_key = Zeroizing::new(file_key);
    let base_nonce = Zeroizing::new(base_nonce);
    drop(shared_secret);

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
