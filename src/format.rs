use anyhow::{Context, Result, anyhow, bail};
use std::io::Read;

use crate::crypto::{
    ENCRYPTED_SEED_LEN, FILE_NONCE_LEN, KEM_CT_LEN, PASSWORD_BLOB_LEN, SEED_TAG_LEN,
};

pub const MAGIC: &[u8; 8] = b"ASYMCRY\0";
pub const VERSION: u8 = 1;
pub const ALG_AEGIS_128X2: u8 = 1;
pub const KDF_ARGON2ID: u8 = 1;
pub const FLAG_PASSWORD_BLOB: u8 = 1;

pub const DEFAULT_CHUNK_SIZE: u32 = 1024 * 1024;
pub const MAX_CHUNK_SIZE: u32 = 64 * 1024 * 1024;

pub const HEADER_FIXED_LEN: usize = 8 + 1 + 1 + 1 + 4 + FILE_NONCE_LEN + 2 + KEM_CT_LEN;
pub const ARGON2_METADATA_LEN: usize = 1 + 16 + 4 + 4 + 4;

pub const FINAL_CHUNK_FLAG: u8 = 1;
pub const CHUNK_FRAMING_LEN: usize = 4 + 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Argon2Meta {
    pub salt: [u8; 16],
    pub mem_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Argon2Meta {
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(ARGON2_METADATA_LEN);
        v.push(KDF_ARGON2ID);
        v.extend_from_slice(&self.salt);
        v.extend_from_slice(&self.mem_kib.to_le_bytes());
        v.extend_from_slice(&self.iterations.to_le_bytes());
        v.extend_from_slice(&self.parallelism.to_le_bytes());
        v
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() != ARGON2_METADATA_LEN {
            bail!("invalid Argon2 metadata length: {}", buf.len());
        }
        if buf[0] != KDF_ARGON2ID {
            bail!("unknown KDF id: {}", buf[0]);
        }
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&buf[1..17]);
        let mem_kib = u32::from_le_bytes(buf[17..21].try_into().unwrap());
        let iterations = u32::from_le_bytes(buf[21..25].try_into().unwrap());
        let parallelism = u32::from_le_bytes(buf[25..29].try_into().unwrap());
        Ok(Self {
            salt,
            mem_kib,
            iterations,
            parallelism,
        })
    }
}

#[derive(Debug, Clone)]
pub struct PasswordBlob {
    pub encrypted_seed: [u8; ENCRYPTED_SEED_LEN],
    pub seed_tag: [u8; SEED_TAG_LEN],
    pub argon2: Argon2Meta,
}

impl PasswordBlob {
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(PASSWORD_BLOB_LEN);
        v.extend_from_slice(&self.encrypted_seed);
        v.extend_from_slice(&self.seed_tag);
        v.extend_from_slice(&self.argon2.encode());
        v
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() != PASSWORD_BLOB_LEN {
            bail!("invalid password blob length: {}", buf.len());
        }
        let mut encrypted_seed = [0u8; ENCRYPTED_SEED_LEN];
        encrypted_seed.copy_from_slice(&buf[..ENCRYPTED_SEED_LEN]);
        let mut seed_tag = [0u8; SEED_TAG_LEN];
        seed_tag.copy_from_slice(&buf[ENCRYPTED_SEED_LEN..ENCRYPTED_SEED_LEN + SEED_TAG_LEN]);
        let argon2 = Argon2Meta::decode(&buf[ENCRYPTED_SEED_LEN + SEED_TAG_LEN..])?;
        Ok(Self {
            encrypted_seed,
            seed_tag,
            argon2,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Header {
    pub chunk_size: u32,
    pub file_nonce: [u8; FILE_NONCE_LEN],
    pub kem_ciphertext: [u8; KEM_CT_LEN],
    pub password_blob: Option<PasswordBlob>,
}

impl Header {
    pub fn encode(&self) -> Vec<u8> {
        let blob_bytes = self
            .password_blob
            .as_ref()
            .map(|b| b.encode())
            .unwrap_or_default();
        let header_len = u16::try_from(blob_bytes.len()).expect("header metadata fits in u16");
        let mut v = Vec::with_capacity(HEADER_FIXED_LEN + blob_bytes.len());
        v.extend_from_slice(MAGIC);
        v.push(VERSION);
        v.push(ALG_AEGIS_128X2);
        v.push(if self.password_blob.is_some() {
            FLAG_PASSWORD_BLOB
        } else {
            0
        });
        v.extend_from_slice(&self.chunk_size.to_le_bytes());
        v.extend_from_slice(&self.file_nonce);
        v.extend_from_slice(&header_len.to_le_bytes());
        v.extend_from_slice(&self.kem_ciphertext);
        v.extend_from_slice(&blob_bytes);
        v
    }

    pub fn read<R: Read>(mut r: R) -> Result<(Self, Vec<u8>)> {
        let mut fixed = [0u8; HEADER_FIXED_LEN];
        r.read_exact(&mut fixed).context("reading header")?;
        if &fixed[0..8] != MAGIC {
            bail!("bad magic bytes; not an asymcrypt stream");
        }
        if fixed[8] != VERSION {
            bail!("unsupported asymcrypt version {}", fixed[8]);
        }
        if fixed[9] != ALG_AEGIS_128X2 {
            bail!("unsupported algorithm id {}", fixed[9]);
        }
        let flags = fixed[10];
        if flags & !FLAG_PASSWORD_BLOB != 0 {
            bail!("unknown header flags: {:#x}", flags);
        }
        let chunk_size = u32::from_le_bytes(fixed[11..15].try_into().unwrap());
        if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
            bail!("invalid chunk size {}", chunk_size);
        }
        let mut file_nonce = [0u8; FILE_NONCE_LEN];
        file_nonce.copy_from_slice(&fixed[15..31]);
        let header_len = u16::from_le_bytes(fixed[31..33].try_into().unwrap()) as usize;
        let mut kem_ciphertext = [0u8; KEM_CT_LEN];
        kem_ciphertext.copy_from_slice(&fixed[33..33 + KEM_CT_LEN]);

        let mut metadata = vec![0u8; header_len];
        r.read_exact(&mut metadata)
            .context("reading header metadata")?;

        let password_blob = if flags & FLAG_PASSWORD_BLOB != 0 {
            Some(PasswordBlob::decode(&metadata)?)
        } else {
            if header_len != 0 {
                bail!("metadata present but no password-blob flag set");
            }
            None
        };

        let mut full = Vec::with_capacity(HEADER_FIXED_LEN + header_len);
        full.extend_from_slice(&fixed);
        full.extend_from_slice(&metadata);
        Ok((
            Self {
                chunk_size,
                file_nonce,
                kem_ciphertext,
                password_blob,
            },
            full,
        ))
    }
}

pub const CHUNK_AD_TRAILER_LEN: usize = 8 + 4 + 1;

pub fn new_chunk_ad(header: &[u8]) -> Vec<u8> {
    let mut ad = Vec::with_capacity(header.len() + CHUNK_AD_TRAILER_LEN);
    ad.extend_from_slice(header);
    ad
}

pub fn update_chunk_ad(
    ad: &mut Vec<u8>,
    header_len: usize,
    chunk_index: u64,
    plain_len: u32,
    flags: u8,
) {
    ad.truncate(header_len);
    ad.extend_from_slice(&chunk_index.to_le_bytes());
    ad.extend_from_slice(&plain_len.to_le_bytes());
    ad.push(flags);
}

pub fn encode_chunk_framing(plain_len: u32, flags: u8) -> [u8; CHUNK_FRAMING_LEN] {
    let mut out = [0u8; CHUNK_FRAMING_LEN];
    out[..4].copy_from_slice(&plain_len.to_le_bytes());
    out[4] = flags;
    out
}

pub fn decode_chunk_framing(buf: &[u8; CHUNK_FRAMING_LEN]) -> (u32, u8) {
    let plain_len = u32::from_le_bytes(buf[..4].try_into().unwrap());
    let flags = buf[4];
    (plain_len, flags)
}

pub fn validate_chunk_flags(flags: u8) -> Result<bool> {
    if flags & !FINAL_CHUNK_FLAG != 0 {
        return Err(anyhow!("unknown chunk flags: {:#x}", flags));
    }
    Ok(flags & FINAL_CHUNK_FLAG != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn header_round_trip_no_blob() {
        let h = Header {
            chunk_size: 64 * 1024,
            file_nonce: [0xa5; FILE_NONCE_LEN],
            kem_ciphertext: [0x33; KEM_CT_LEN],
            password_blob: None,
        };
        let bytes = h.encode();
        let mut cur = Cursor::new(&bytes);
        let (parsed, raw) = Header::read(&mut cur).unwrap();
        assert_eq!(parsed.chunk_size, h.chunk_size);
        assert_eq!(parsed.file_nonce, h.file_nonce);
        assert_eq!(parsed.kem_ciphertext, h.kem_ciphertext);
        assert!(parsed.password_blob.is_none());
        assert_eq!(raw, bytes);
    }

    #[test]
    fn header_round_trip_with_blob() {
        let h = Header {
            chunk_size: DEFAULT_CHUNK_SIZE,
            file_nonce: [0x11; FILE_NONCE_LEN],
            kem_ciphertext: [0x55; KEM_CT_LEN],
            password_blob: Some(PasswordBlob {
                encrypted_seed: [0xaa; ENCRYPTED_SEED_LEN],
                seed_tag: [0xbb; SEED_TAG_LEN],
                argon2: Argon2Meta {
                    salt: [0x33; 16],
                    mem_kib: 65536,
                    iterations: 3,
                    parallelism: 4,
                },
            }),
        };
        let bytes = h.encode();
        let (parsed, raw) = Header::read(&mut Cursor::new(&bytes)).unwrap();
        let blob = parsed.password_blob.unwrap();
        assert_eq!(blob.encrypted_seed, [0xaa; ENCRYPTED_SEED_LEN]);
        assert_eq!(blob.seed_tag, [0xbb; SEED_TAG_LEN]);
        assert_eq!(blob.argon2, h.password_blob.unwrap().argon2);
        assert_eq!(raw, bytes);
    }

    #[test]
    fn header_rejects_bad_magic() {
        let mut bytes = Header {
            chunk_size: 1024,
            file_nonce: [0; FILE_NONCE_LEN],
            kem_ciphertext: [0; KEM_CT_LEN],
            password_blob: None,
        }
        .encode();
        bytes[0] = b'X';
        assert!(Header::read(&mut Cursor::new(&bytes)).is_err());
    }

    #[test]
    fn header_rejects_zero_chunk_size() {
        let mut bytes = Header {
            chunk_size: 1,
            file_nonce: [0; FILE_NONCE_LEN],
            kem_ciphertext: [0; KEM_CT_LEN],
            password_blob: None,
        }
        .encode();
        bytes[11..15].copy_from_slice(&0u32.to_le_bytes());
        assert!(Header::read(&mut Cursor::new(&bytes)).is_err());
    }

    #[test]
    fn header_rejects_oversized_chunk() {
        let mut bytes = Header {
            chunk_size: 1,
            file_nonce: [0; FILE_NONCE_LEN],
            kem_ciphertext: [0; KEM_CT_LEN],
            password_blob: None,
        }
        .encode();
        bytes[11..15].copy_from_slice(&(MAX_CHUNK_SIZE + 1).to_le_bytes());
        assert!(Header::read(&mut Cursor::new(&bytes)).is_err());
    }

    #[test]
    fn password_blob_round_trip() {
        let blob = PasswordBlob {
            encrypted_seed: [0x11; ENCRYPTED_SEED_LEN],
            seed_tag: [0x22; SEED_TAG_LEN],
            argon2: Argon2Meta {
                salt: [0x44; 16],
                mem_kib: 32768,
                iterations: 2,
                parallelism: 1,
            },
        };
        let encoded = blob.encode();
        assert_eq!(encoded.len(), PASSWORD_BLOB_LEN);
        let decoded = PasswordBlob::decode(&encoded).unwrap();
        assert_eq!(decoded.encrypted_seed, blob.encrypted_seed);
        assert_eq!(decoded.seed_tag, blob.seed_tag);
        assert_eq!(decoded.argon2, blob.argon2);
    }
}
