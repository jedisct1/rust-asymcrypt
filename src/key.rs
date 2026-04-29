use anyhow::{Context, Result, bail};
use fs2::FileExt;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;
use zeroize::Zeroize;

use crate::crypto::MASTER_KEY_LEN;
use crate::format::{ARGON2_METADATA_LEN, Argon2Meta};
use crate::io::{CommitOutcome, parent_or_cwd, sync_dir};

/// v1 plain chain key: type byte + 32 raw key bytes. Used by `encrypt`,
/// rotated in place.
pub const KEY_TYPE_PLAIN_V1: u8 = 0x01;
/// v1 composite chain key: type byte + 32 raw key bytes + 29 bytes Argon2
/// metadata. Used by `encrypt`, rotated in place.
pub const KEY_TYPE_COMPOSITE_V1: u8 = 0x02;
/// v1 plain recovery key: type byte + 32 raw key bytes. Used by
/// `decrypt --key-file`; never modified by any tool.
pub const KEY_TYPE_RECOVERY_V1: u8 = 0x03;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFileFormat {
    Raw,
    Hex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRole {
    /// On-device chain key (`0x01` or `0x02`). Encryptable input.
    Chain,
    /// Offline recovery key (`0x03`). Decryption-only input.
    Recovery,
}

#[derive(Debug, Clone, Copy)]
pub enum KeyKind<'a> {
    PlainChain,
    CompositeChain(&'a Argon2Meta),
    PlainRecovery,
}

impl<'a> KeyKind<'a> {
    fn type_byte(&self) -> u8 {
        match self {
            KeyKind::PlainChain => KEY_TYPE_PLAIN_V1,
            KeyKind::CompositeChain(_) => KEY_TYPE_COMPOSITE_V1,
            KeyKind::PlainRecovery => KEY_TYPE_RECOVERY_V1,
        }
    }

    pub fn chain_from_kdf(kdf: Option<&'a Argon2Meta>) -> Self {
        match kdf {
            Some(meta) => KeyKind::CompositeChain(meta),
            None => KeyKind::PlainChain,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ParsedKeyFile {
    pub key: [u8; MASTER_KEY_LEN],
    pub kdf: Option<Argon2Meta>,
    pub format: KeyFileFormat,
    pub role: KeyRole,
}

pub fn parse_key_file(bytes: &[u8]) -> Result<ParsedKeyFile> {
    if let Some(parsed) = try_parse_raw(bytes, KeyFileFormat::Raw)? {
        return Ok(parsed);
    }
    let trimmed: Vec<u8> = bytes
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if !trimmed.is_empty()
        && trimmed.len().is_multiple_of(2)
        && trimmed.iter().all(|b| b.is_ascii_hexdigit())
    {
        let mut decoded = vec![0u8; trimmed.len() / 2];
        hex::decode_to_slice(&trimmed, &mut decoded).context("invalid hex key")?;
        let parsed = try_parse_raw(&decoded, KeyFileFormat::Hex)?
            .ok_or_else(|| anyhow::anyhow!("hex key payload has unknown type/version"))?;
        decoded.zeroize();
        return Ok(parsed);
    }
    bail!("not a recognised asymcrypt key file");
}

fn try_parse_raw(bytes: &[u8], format: KeyFileFormat) -> Result<Option<ParsedKeyFile>> {
    let Some(&tag) = bytes.first() else {
        return Ok(None);
    };
    let (label, role, expected_extra, has_kdf) = match tag {
        KEY_TYPE_PLAIN_V1 => ("plain", KeyRole::Chain, 0, false),
        KEY_TYPE_COMPOSITE_V1 => ("composite", KeyRole::Chain, ARGON2_METADATA_LEN, true),
        KEY_TYPE_RECOVERY_V1 => ("recovery", KeyRole::Recovery, 0, false),
        _ => return Ok(None),
    };
    let body = &bytes[1..];
    let want = MASTER_KEY_LEN + expected_extra;
    if body.len() != want {
        bail!(
            "{} key file body must be {} bytes, got {}",
            label,
            want,
            body.len()
        );
    }
    let mut key = [0u8; MASTER_KEY_LEN];
    key.copy_from_slice(&body[..MASTER_KEY_LEN]);
    let kdf = if has_kdf {
        Some(Argon2Meta::decode(&body[MASTER_KEY_LEN..])?)
    } else {
        None
    };
    Ok(Some(ParsedKeyFile {
        key,
        kdf,
        format,
        role,
    }))
}

pub fn encode_key_file(
    key: &[u8; MASTER_KEY_LEN],
    kind: KeyKind<'_>,
    format: KeyFileFormat,
) -> Vec<u8> {
    let mut raw: Vec<u8> = Vec::with_capacity(1 + MASTER_KEY_LEN + ARGON2_METADATA_LEN);
    raw.push(kind.type_byte());
    raw.extend_from_slice(key);
    if let KeyKind::CompositeChain(meta) = kind {
        raw.extend_from_slice(&meta.encode());
    }
    match format {
        KeyFileFormat::Raw => raw,
        KeyFileFormat::Hex => {
            let mut s = hex::encode(&raw).into_bytes();
            raw.zeroize();
            s.push(b'\n');
            s
        }
    }
}

pub fn lock_path(key_path: &Path) -> PathBuf {
    let mut s = key_path.as_os_str().to_owned();
    s.push(".lock");
    PathBuf::from(s)
}

pub struct KeyLock {
    file: File,
}

impl KeyLock {
    pub fn acquire(key_path: &Path) -> Result<Self> {
        let path = lock_path(key_path);
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .with_context(|| format!("opening lock file {}", path.display()))?;
        FileExt::lock_exclusive(&file).with_context(|| format!("locking {}", path.display()))?;
        Ok(Self { file })
    }
}

impl Drop for KeyLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

#[cfg(unix)]
pub fn check_key_permissions(path: &Path, allow_insecure: bool) -> Result<u32> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    let mode = meta.permissions().mode() & 0o777;
    if !allow_insecure && (mode & 0o077) != 0 {
        bail!(
            "key file {} has insecure permissions {:o}; chmod 600 it or pass --insecure-perms",
            path.display(),
            mode
        );
    }
    Ok(mode)
}

#[cfg(not(unix))]
pub fn check_key_permissions(_path: &Path, _allow_insecure: bool) -> Result<u32> {
    Ok(0)
}

/// Atomically write `bytes` to `path` via a staged tempfile and
/// `persist_noclobber` (refuses overwrite). After a successful rename, a
/// parent-directory fsync failure is reported through
/// `CommitOutcome::dir_sync_warning` rather than `Err`, since the file is
/// already on disk and the caller would otherwise need rollback semantics for
/// an already-committed write.
pub fn write_new_file_durable(
    path: &Path,
    bytes: &[u8],
    mode: Option<u32>,
) -> Result<CommitOutcome> {
    let parent = parent_or_cwd(path);
    let mut tmp = NamedTempFile::new_in(parent)
        .with_context(|| format!("creating temp file in {}", parent.display()))?;
    tmp.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Some(m) = mode {
            std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(m))
                .with_context(|| format!("setting mode on staged {}", path.display()))?;
        }
    }
    #[cfg(not(unix))]
    let _ = mode;
    tmp.as_file()
        .sync_all()
        .with_context(|| format!("fsync staged {}", path.display()))?;
    tmp.persist_noclobber(path)
        .map_err(|e| anyhow::anyhow!("persist {}: {}", path.display(), e.error))?;
    let dir_sync_warning = sync_dir(parent).err();
    Ok(CommitOutcome { dir_sync_warning })
}

/// A next-key file staged in the destination directory but not yet renamed
/// into place. Dropping without [`commit`] leaves the live key untouched.
pub struct StagedKeyReplacement {
    tmp: NamedTempFile,
    dest: PathBuf,
}

impl StagedKeyReplacement {
    /// Atomically rotate the key file. Errors mean the live key was *not*
    /// updated. After a successful rename, a parent-directory fsync failure
    /// is reported via `CommitOutcome::dir_sync_warning` rather than `Err`.
    pub fn commit(self) -> Result<CommitOutcome> {
        let dest = self.dest;
        self.tmp
            .persist(&dest)
            .map_err(|e| anyhow::anyhow!("persist key file: {}", e.error))?;
        let dir_sync_warning = dest
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .and_then(|p| sync_dir(p).err());
        Ok(CommitOutcome { dir_sync_warning })
    }
}

/// Stage a new key file alongside `key_path`. The actual key swap happens
/// in [`StagedKeyReplacement::commit`], which must run *after* the
/// encryption output has been committed.
pub fn stage_key_replacement(
    key_path: &Path,
    new_key: &[u8; MASTER_KEY_LEN],
    kind: KeyKind<'_>,
    format: KeyFileFormat,
    preserve_mode: Option<u32>,
) -> Result<StagedKeyReplacement> {
    let parent = parent_or_cwd(key_path);
    let mut tmp = NamedTempFile::new_in(parent)
        .with_context(|| format!("creating temp file in {}", parent.display()))?;
    let mut bytes = encode_key_file(new_key, kind, format);
    tmp.write_all(&bytes)?;
    bytes.zeroize();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Some(mode) = preserve_mode {
            let perms = std::fs::Permissions::from_mode(mode);
            std::fs::set_permissions(tmp.path(), perms)?;
        }
    }
    #[cfg(not(unix))]
    let _ = preserve_mode;
    tmp.as_file().sync_all()?;
    sync_dir(parent).with_context(|| format!("syncing {}", parent.display()))?;
    Ok(StagedKeyReplacement {
        tmp,
        dest: key_path.to_path_buf(),
    })
}

pub fn random_key() -> Result<[u8; MASTER_KEY_LEN]> {
    let mut k = [0u8; MASTER_KEY_LEN];
    getrandom::fill(&mut k).context("getrandom failed")?;
    Ok(k)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_meta() -> Argon2Meta {
        Argon2Meta {
            salt: [0x33; 16],
            mem_kib: 65536,
            iterations: 3,
            parallelism: 4,
        }
    }

    #[test]
    fn parse_raw_plain_key() {
        let key = [7u8; MASTER_KEY_LEN];
        let mut bytes = vec![KEY_TYPE_PLAIN_V1];
        bytes.extend_from_slice(&key);
        let parsed = parse_key_file(&bytes).unwrap();
        assert_eq!(parsed.key, key);
        assert!(parsed.kdf.is_none());
        assert_eq!(parsed.format, KeyFileFormat::Raw);
        assert_eq!(parsed.role, KeyRole::Chain);
    }

    #[test]
    fn parse_raw_composite_key() {
        let key = [0xa5u8; MASTER_KEY_LEN];
        let meta = sample_meta();
        let bytes = encode_key_file(&key, KeyKind::CompositeChain(&meta), KeyFileFormat::Raw);
        let parsed = parse_key_file(&bytes).unwrap();
        assert_eq!(parsed.key, key);
        assert_eq!(parsed.kdf.unwrap(), meta);
        assert_eq!(parsed.format, KeyFileFormat::Raw);
        assert_eq!(parsed.role, KeyRole::Chain);
    }

    #[test]
    fn parse_raw_recovery_key() {
        let key = [0x5au8; MASTER_KEY_LEN];
        let bytes = encode_key_file(&key, KeyKind::PlainRecovery, KeyFileFormat::Raw);
        assert_eq!(bytes[0], KEY_TYPE_RECOVERY_V1);
        assert_eq!(bytes.len(), 1 + MASTER_KEY_LEN);
        let parsed = parse_key_file(&bytes).unwrap();
        assert_eq!(parsed.key, key);
        assert!(parsed.kdf.is_none());
        assert_eq!(parsed.format, KeyFileFormat::Raw);
        assert_eq!(parsed.role, KeyRole::Recovery);
    }

    #[test]
    fn parse_hex_plain_key() {
        let key = [0x11u8; MASTER_KEY_LEN];
        let bytes = encode_key_file(&key, KeyKind::PlainChain, KeyFileFormat::Hex);
        let parsed = parse_key_file(&bytes).unwrap();
        assert_eq!(parsed.key, key);
        assert!(parsed.kdf.is_none());
        assert_eq!(parsed.format, KeyFileFormat::Hex);
        assert_eq!(parsed.role, KeyRole::Chain);
    }

    #[test]
    fn parse_hex_recovery_key() {
        let key = [0x99u8; MASTER_KEY_LEN];
        let bytes = encode_key_file(&key, KeyKind::PlainRecovery, KeyFileFormat::Hex);
        assert!(bytes.iter().all(|b| b.is_ascii_hexdigit() || *b == b'\n'));
        let parsed = parse_key_file(&bytes).unwrap();
        assert_eq!(parsed.key, key);
        assert_eq!(parsed.role, KeyRole::Recovery);
        assert_eq!(parsed.format, KeyFileFormat::Hex);
    }

    #[test]
    fn parse_hex_composite_key_with_whitespace() {
        let key = [0x22u8; MASTER_KEY_LEN];
        let meta = sample_meta();
        let mut bytes = encode_key_file(&key, KeyKind::CompositeChain(&meta), KeyFileFormat::Hex);
        let mut padded = b"   ".to_vec();
        padded.append(&mut bytes);
        padded.extend_from_slice(b"\n  \n");
        let parsed = parse_key_file(&padded).unwrap();
        assert_eq!(parsed.key, key);
        assert_eq!(parsed.kdf.unwrap(), meta);
        assert_eq!(parsed.format, KeyFileFormat::Hex);
        assert_eq!(parsed.role, KeyRole::Chain);
    }

    #[test]
    fn rejects_short_input() {
        assert!(parse_key_file(&[]).is_err());
        assert!(parse_key_file(&[KEY_TYPE_PLAIN_V1, 1, 2, 3]).is_err());
    }

    #[test]
    fn rejects_recovery_body_wrong_length() {
        let mut bytes = vec![KEY_TYPE_RECOVERY_V1];
        bytes.extend_from_slice(&[0u8; MASTER_KEY_LEN - 1]);
        assert!(parse_key_file(&bytes).is_err());
        let mut bytes = vec![KEY_TYPE_RECOVERY_V1];
        bytes.extend_from_slice(&[0u8; MASTER_KEY_LEN + 1]);
        assert!(parse_key_file(&bytes).is_err());
    }

    #[test]
    fn rejects_unknown_type() {
        let mut bytes = vec![0xffu8];
        bytes.extend_from_slice(&[0u8; MASTER_KEY_LEN]);
        assert!(parse_key_file(&bytes).is_err());
    }

    #[test]
    fn rejects_bad_hex() {
        assert!(parse_key_file(b"zz112233445566778899aabbccddeeff").is_err());
    }

    #[test]
    fn encode_recovery_first_byte() {
        let key = [0u8; MASTER_KEY_LEN];
        let raw = encode_key_file(&key, KeyKind::PlainRecovery, KeyFileFormat::Raw);
        assert_eq!(raw[0], KEY_TYPE_RECOVERY_V1);
        assert_eq!(raw.len(), 1 + MASTER_KEY_LEN);
    }

    #[test]
    fn lock_path_appends_suffix() {
        let p = Path::new("/tmp/k.key");
        assert_eq!(lock_path(p), PathBuf::from("/tmp/k.key.lock"));
    }
}
