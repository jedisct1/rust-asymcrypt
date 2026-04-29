use aegis::aegis128x2::Aegis128X2;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

pub const MASTER_KEY_LEN: usize = 32;
pub const CIPHER_KEY_LEN: usize = 16;
pub const TAG_LEN: usize = 32;
pub const NONCE_LEN: usize = 16;
pub const FILE_NONCE_LEN: usize = 16;
pub const KEY_CHECK_LEN: usize = 32;

pub const KEY_EVOLUTION_LABEL: &[u8] = b"asymcrypt key evolution v1";
pub const FILE_DERIVATION_LABEL: &[u8] = b"asymcrypt file derivation v1";
pub const KEY_CHECK_LABEL: &[u8] = b"asymcrypt key check v1";

type HmacSha256 = Hmac<Sha256>;

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    for p in parts {
        mac.update(p);
    }
    let mut out = mac.finalize().into_bytes();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&out);
    let slice: &mut [u8] = out.as_mut();
    slice.zeroize();
    buf
}

pub fn evolve_key(key: &mut [u8; MASTER_KEY_LEN]) {
    let mut full = hmac_sha256(key, &[KEY_EVOLUTION_LABEL]);
    key.copy_from_slice(&full);
    full.zeroize();
}

pub fn derive_file_secrets(
    stream_key: &[u8; MASTER_KEY_LEN],
    file_nonce: &[u8; FILE_NONCE_LEN],
) -> ([u8; CIPHER_KEY_LEN], [u8; NONCE_LEN]) {
    let mut full = hmac_sha256(stream_key, &[FILE_DERIVATION_LABEL, file_nonce]);
    let mut file_key = [0u8; CIPHER_KEY_LEN];
    let mut base_nonce = [0u8; NONCE_LEN];
    file_key.copy_from_slice(&full[..CIPHER_KEY_LEN]);
    base_nonce.copy_from_slice(&full[CIPHER_KEY_LEN..CIPHER_KEY_LEN + NONCE_LEN]);
    full.zeroize();
    (file_key, base_nonce)
}

pub fn derive_chunk_nonce(base_nonce: &[u8; NONCE_LEN], chunk_index: u64) -> [u8; NONCE_LEN] {
    let mut nonce = *base_nonce;
    let idx = chunk_index.to_le_bytes();
    for (b, c) in nonce[..idx.len()].iter_mut().zip(idx.iter()) {
        *b ^= *c;
    }
    nonce
}

pub fn key_check(
    stream_key: &[u8; MASTER_KEY_LEN],
    file_nonce: &[u8; FILE_NONCE_LEN],
) -> [u8; KEY_CHECK_LEN] {
    hmac_sha256(stream_key, &[KEY_CHECK_LABEL, file_nonce])
}

/// In-place AEGIS-128X2 encryption. `buf` is overwritten with ciphertext;
/// the returned 16-byte tag must be appended to the stream.
pub fn encrypt_chunk_in_place(
    key: &[u8; CIPHER_KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    buf: &mut [u8],
    ad: &[u8],
) -> [u8; TAG_LEN] {
    Aegis128X2::<TAG_LEN>::new(key, nonce).encrypt_in_place(buf, ad)
}

/// In-place AEGIS-128X2 decryption. `buf` enters as ciphertext and exits as
/// authenticated plaintext. On `Err`, `buf` may be in an indeterminate state
/// and the caller must not surface its bytes.
pub fn decrypt_chunk_in_place(
    key: &[u8; CIPHER_KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    buf: &mut [u8],
    tag: &[u8; TAG_LEN],
    ad: &[u8],
) -> Result<(), aegis::Error> {
    Aegis128X2::<TAG_LEN>::new(key, nonce).decrypt_in_place(buf, tag, ad)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expected_hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(key).unwrap();
        for p in parts {
            mac.update(p);
        }
        let out = mac.finalize().into_bytes();
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&out);
        buf
    }

    #[test]
    fn evolve_is_deterministic() {
        let mut a = [0x42u8; MASTER_KEY_LEN];
        let mut b = [0x42u8; MASTER_KEY_LEN];
        evolve_key(&mut a);
        evolve_key(&mut b);
        assert_eq!(a, b);
        assert_ne!(a, [0x42u8; MASTER_KEY_LEN]);
    }

    #[test]
    fn evolve_changes_key() {
        let mut k = [0u8; MASTER_KEY_LEN];
        let original = k;
        evolve_key(&mut k);
        assert_ne!(k, original);
    }

    #[test]
    fn evolve_known_vector() {
        let mut k = [0u8; MASTER_KEY_LEN];
        evolve_key(&mut k);
        let expected = expected_hmac(&[0u8; MASTER_KEY_LEN], &[KEY_EVOLUTION_LABEL]);
        assert_eq!(&k[..], &expected[..]);
    }

    #[test]
    fn derive_file_secrets_is_deterministic() {
        let k = [0x42u8; MASTER_KEY_LEN];
        let fnz = [0x9eu8; FILE_NONCE_LEN];
        let a = derive_file_secrets(&k, &fnz);
        let b = derive_file_secrets(&k, &fnz);
        assert_eq!(a, b);
    }

    #[test]
    fn derive_file_secrets_depends_on_each_input() {
        let k1 = [1u8; MASTER_KEY_LEN];
        let k2 = [2u8; MASTER_KEY_LEN];
        let fn1 = [0x55u8; FILE_NONCE_LEN];
        let fn2 = [0xaau8; FILE_NONCE_LEN];
        let a = derive_file_secrets(&k1, &fn1);
        let b = derive_file_secrets(&k2, &fn1);
        let c = derive_file_secrets(&k1, &fn2);
        assert_ne!(a.0, b.0);
        assert_ne!(a.1, b.1);
        assert_ne!(a.0, c.0);
        assert_ne!(a.1, c.1);
    }

    #[test]
    fn derive_file_secrets_halves_differ() {
        let k = [0u8; MASTER_KEY_LEN];
        let fnz = [0u8; FILE_NONCE_LEN];
        let (file_key, base_nonce) = derive_file_secrets(&k, &fnz);
        assert_ne!(file_key, base_nonce);
    }

    #[test]
    fn derive_file_secrets_known_vector() {
        let k = [0u8; MASTER_KEY_LEN];
        let fnz = [0u8; FILE_NONCE_LEN];
        let (file_key, base_nonce) = derive_file_secrets(&k, &fnz);
        let expected = expected_hmac(&k, &[FILE_DERIVATION_LABEL, &fnz]);
        assert_eq!(&file_key[..], &expected[..CIPHER_KEY_LEN]);
        assert_eq!(
            &base_nonce[..],
            &expected[CIPHER_KEY_LEN..CIPHER_KEY_LEN + NONCE_LEN]
        );
    }

    #[test]
    fn chunk_nonce_xor_counter() {
        let base = [
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0,
            0xf0, 0x00,
        ];
        for &i in &[0u64, 1, 0xff, 0x1234_5678, u64::MAX] {
            let got = derive_chunk_nonce(&base, i);
            let mut want = base;
            for (b, c) in want[..8].iter_mut().zip(i.to_le_bytes().iter()) {
                *b ^= *c;
            }
            assert_eq!(got, want, "i = {i:#x}");
        }
    }

    #[test]
    fn chunk_nonce_high_half_is_invariant() {
        let base = [0x77u8; NONCE_LEN];
        for &i in &[0u64, 1, 0x100, u64::MAX] {
            let n = derive_chunk_nonce(&base, i);
            assert_eq!(&n[8..], &base[8..]);
        }
    }

    #[test]
    fn key_check_matches_label() {
        let k = [0xabu8; MASTER_KEY_LEN];
        let fnz = [0x5cu8; FILE_NONCE_LEN];
        let kc = key_check(&k, &fnz);
        let expected = expected_hmac(&k, &[KEY_CHECK_LABEL, &fnz]);
        assert_eq!(&kc[..], &expected[..]);
    }

    #[test]
    fn key_check_binds_to_file_nonce() {
        let k = [0xabu8; MASTER_KEY_LEN];
        let a = key_check(&k, &[0u8; FILE_NONCE_LEN]);
        let b = key_check(&k, &[1u8; FILE_NONCE_LEN]);
        assert_ne!(a, b);
    }

    #[test]
    fn aegis_round_trip() {
        let key = [9u8; CIPHER_KEY_LEN];
        let nonce = [3u8; NONCE_LEN];
        let m: &[u8] = b"the quick brown fox jumps over the lazy dog";
        let ad = b"AD";
        let mut buf = m.to_vec();
        let tag = encrypt_chunk_in_place(&key, &nonce, &mut buf, ad);
        assert_ne!(buf, m);
        decrypt_chunk_in_place(&key, &nonce, &mut buf, &tag, ad).unwrap();
        assert_eq!(buf, m);
        let mut bad_tag = tag;
        bad_tag[0] ^= 1;
        let mut buf2 = m.to_vec();
        let _ = encrypt_chunk_in_place(&key, &nonce, &mut buf2, ad);
        assert!(decrypt_chunk_in_place(&key, &nonce, &mut buf2, &bad_tag, ad).is_err());
    }
}
