use anyhow::{Context, Result, bail};
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{DK_SEED_LEN, EK_LEN, PASSWORD_BLOB_LEN};
use crate::io::{CommitOutcome, parent_or_cwd, sync_dir};

/// 0x01: encapsulation key only (public, on device).
pub const KEY_TYPE_EK: u8 = 0x01;
/// 0x02: encapsulation key + encrypted dk seed + Argon2 params (password mode).
pub const KEY_TYPE_COMPOSITE: u8 = 0x02;
/// 0x03: decapsulation key seed (private, offline recovery).
pub const KEY_TYPE_DK_SEED: u8 = 0x03;

pub const EK_FILE_LEN: usize = 1 + EK_LEN;
pub const DK_SEED_FILE_LEN: usize = 1 + DK_SEED_LEN;
pub const COMPOSITE_FILE_LEN: usize = 1 + EK_LEN + PASSWORD_BLOB_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFileFormat {
    Raw,
    Hex,
}

#[derive(Debug, Clone)]
pub enum ParsedKeyFile {
    EncapsulationKey {
        ek_bytes: [u8; EK_LEN],
        format: KeyFileFormat,
    },
    Composite {
        ek_bytes: [u8; EK_LEN],
        password_blob: Zeroizing<Vec<u8>>,
        format: KeyFileFormat,
    },
    DecapsulationSeed {
        seed: [u8; DK_SEED_LEN],
        format: KeyFileFormat,
    },
}

impl ParsedKeyFile {
    pub fn is_public(&self) -> bool {
        matches!(self, ParsedKeyFile::EncapsulationKey { .. })
    }
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
    let body = &bytes[1..];
    match tag {
        KEY_TYPE_EK => {
            if body.len() != EK_LEN {
                bail!(
                    "encapsulation key file body must be {} bytes, got {}",
                    EK_LEN,
                    body.len()
                );
            }
            let mut ek_bytes = [0u8; EK_LEN];
            ek_bytes.copy_from_slice(body);
            Ok(Some(ParsedKeyFile::EncapsulationKey { ek_bytes, format }))
        }
        KEY_TYPE_COMPOSITE => {
            let expected = EK_LEN + PASSWORD_BLOB_LEN;
            if body.len() != expected {
                bail!(
                    "composite key file body must be {} bytes, got {}",
                    expected,
                    body.len()
                );
            }
            let mut ek_bytes = [0u8; EK_LEN];
            ek_bytes.copy_from_slice(&body[..EK_LEN]);
            let password_blob = Zeroizing::new(body[EK_LEN..].to_vec());
            Ok(Some(ParsedKeyFile::Composite {
                ek_bytes,
                password_blob,
                format,
            }))
        }
        KEY_TYPE_DK_SEED => {
            if body.len() != DK_SEED_LEN {
                bail!(
                    "decapsulation seed file body must be {} bytes, got {}",
                    DK_SEED_LEN,
                    body.len()
                );
            }
            let mut seed = [0u8; DK_SEED_LEN];
            seed.copy_from_slice(body);
            Ok(Some(ParsedKeyFile::DecapsulationSeed { seed, format }))
        }
        _ => Ok(None),
    }
}

pub fn encode_ek_file(ek_bytes: &[u8; EK_LEN], format: KeyFileFormat) -> Vec<u8> {
    let mut raw = Vec::with_capacity(EK_FILE_LEN);
    raw.push(KEY_TYPE_EK);
    raw.extend_from_slice(ek_bytes);
    format_output(raw, format)
}

pub fn encode_composite_file(
    ek_bytes: &[u8; EK_LEN],
    password_blob: &[u8],
    format: KeyFileFormat,
) -> Vec<u8> {
    assert_eq!(password_blob.len(), PASSWORD_BLOB_LEN);
    let mut raw = Vec::with_capacity(COMPOSITE_FILE_LEN);
    raw.push(KEY_TYPE_COMPOSITE);
    raw.extend_from_slice(ek_bytes);
    raw.extend_from_slice(password_blob);
    format_output(raw, format)
}

pub fn encode_dk_seed_file(seed: &[u8; DK_SEED_LEN], format: KeyFileFormat) -> Vec<u8> {
    let mut raw = Vec::with_capacity(DK_SEED_FILE_LEN);
    raw.push(KEY_TYPE_DK_SEED);
    raw.extend_from_slice(seed);
    format_output(raw, format)
}

fn format_output(mut raw: Vec<u8>, format: KeyFileFormat) -> Vec<u8> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_raw_ek() {
        let ek = [7u8; EK_LEN];
        let bytes = encode_ek_file(&ek, KeyFileFormat::Raw);
        assert_eq!(bytes.len(), EK_FILE_LEN);
        assert_eq!(bytes[0], KEY_TYPE_EK);
        let parsed = parse_key_file(&bytes).unwrap();
        match parsed {
            ParsedKeyFile::EncapsulationKey { ek_bytes, format } => {
                assert_eq!(ek_bytes, ek);
                assert_eq!(format, KeyFileFormat::Raw);
            }
            _ => panic!("expected EncapsulationKey"),
        }
    }

    #[test]
    fn parse_raw_dk_seed() {
        let seed = [0x5au8; DK_SEED_LEN];
        let bytes = encode_dk_seed_file(&seed, KeyFileFormat::Raw);
        assert_eq!(bytes.len(), DK_SEED_FILE_LEN);
        assert_eq!(bytes[0], KEY_TYPE_DK_SEED);
        let parsed = parse_key_file(&bytes).unwrap();
        match parsed {
            ParsedKeyFile::DecapsulationSeed {
                seed: s, format, ..
            } => {
                assert_eq!(s, seed);
                assert_eq!(format, KeyFileFormat::Raw);
            }
            _ => panic!("expected DecapsulationSeed"),
        }
    }

    #[test]
    fn parse_raw_composite() {
        let ek = [0xa5u8; EK_LEN];
        let blob = vec![0x33u8; PASSWORD_BLOB_LEN];
        let bytes = encode_composite_file(&ek, &blob, KeyFileFormat::Raw);
        assert_eq!(bytes.len(), COMPOSITE_FILE_LEN);
        assert_eq!(bytes[0], KEY_TYPE_COMPOSITE);
        let parsed = parse_key_file(&bytes).unwrap();
        match parsed {
            ParsedKeyFile::Composite {
                ek_bytes,
                password_blob,
                format,
            } => {
                assert_eq!(ek_bytes, ek);
                assert_eq!(*password_blob, blob);
                assert_eq!(format, KeyFileFormat::Raw);
            }
            _ => panic!("expected Composite"),
        }
    }

    #[test]
    fn parse_hex_ek() {
        let ek = [0x11u8; EK_LEN];
        let bytes = encode_ek_file(&ek, KeyFileFormat::Hex);
        let parsed = parse_key_file(&bytes).unwrap();
        match parsed {
            ParsedKeyFile::EncapsulationKey { ek_bytes, format } => {
                assert_eq!(ek_bytes, ek);
                assert_eq!(format, KeyFileFormat::Hex);
            }
            _ => panic!("expected EncapsulationKey"),
        }
    }

    #[test]
    fn parse_hex_dk_seed() {
        let seed = [0x99u8; DK_SEED_LEN];
        let bytes = encode_dk_seed_file(&seed, KeyFileFormat::Hex);
        assert!(bytes.iter().all(|b| b.is_ascii_hexdigit() || *b == b'\n'));
        let parsed = parse_key_file(&bytes).unwrap();
        match parsed {
            ParsedKeyFile::DecapsulationSeed {
                seed: s, format, ..
            } => {
                assert_eq!(s, seed);
                assert_eq!(format, KeyFileFormat::Hex);
            }
            _ => panic!("expected DecapsulationSeed"),
        }
    }

    #[test]
    fn parse_hex_composite_with_whitespace() {
        let ek = [0x22u8; EK_LEN];
        let blob = vec![0x44u8; PASSWORD_BLOB_LEN];
        let mut bytes = encode_composite_file(&ek, &blob, KeyFileFormat::Hex);
        let mut padded = b"   ".to_vec();
        padded.append(&mut bytes);
        padded.extend_from_slice(b"\n  \n");
        let parsed = parse_key_file(&padded).unwrap();
        match parsed {
            ParsedKeyFile::Composite {
                ek_bytes,
                password_blob,
                format,
            } => {
                assert_eq!(ek_bytes, ek);
                assert_eq!(*password_blob, blob);
                assert_eq!(format, KeyFileFormat::Hex);
            }
            _ => panic!("expected Composite"),
        }
    }

    #[test]
    fn rejects_short_input() {
        assert!(parse_key_file(&[]).is_err());
        assert!(parse_key_file(&[KEY_TYPE_EK, 1, 2, 3]).is_err());
    }

    #[test]
    fn rejects_dk_seed_wrong_length() {
        let mut bytes = vec![KEY_TYPE_DK_SEED];
        bytes.extend_from_slice(&[0u8; DK_SEED_LEN - 1]);
        assert!(parse_key_file(&bytes).is_err());
        let mut bytes = vec![KEY_TYPE_DK_SEED];
        bytes.extend_from_slice(&[0u8; DK_SEED_LEN + 1]);
        assert!(parse_key_file(&bytes).is_err());
    }

    #[test]
    fn rejects_unknown_type() {
        let mut bytes = vec![0xffu8];
        bytes.extend_from_slice(&[0u8; EK_LEN]);
        assert!(parse_key_file(&bytes).is_err());
    }

    #[test]
    fn ek_is_public() {
        let ek = [0u8; EK_LEN];
        let bytes = encode_ek_file(&ek, KeyFileFormat::Raw);
        let parsed = parse_key_file(&bytes).unwrap();
        assert!(parsed.is_public());
    }

    #[test]
    fn dk_seed_is_not_public() {
        let seed = [0u8; DK_SEED_LEN];
        let bytes = encode_dk_seed_file(&seed, KeyFileFormat::Raw);
        let parsed = parse_key_file(&bytes).unwrap();
        assert!(!parsed.is_public());
    }

    #[test]
    fn composite_is_not_public() {
        let ek = [0u8; EK_LEN];
        let blob = vec![0u8; PASSWORD_BLOB_LEN];
        let bytes = encode_composite_file(&ek, &blob, KeyFileFormat::Raw);
        let parsed = parse_key_file(&bytes).unwrap();
        assert!(!parsed.is_public());
    }
}
