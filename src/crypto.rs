use aegis::aegis128x2::Aegis128X2;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use x_wing::kem::{Decapsulate, Encapsulate};
use x_wing::{DecapsulationKey, EncapsulationKey, Kem, KeyExport, TryKeyInit, XWingKem};
use zeroize::Zeroize;

pub const CIPHER_KEY_LEN: usize = 16;
pub const TAG_LEN: usize = 32;
pub const NONCE_LEN: usize = 16;
pub const FILE_NONCE_LEN: usize = 16;

pub const EK_LEN: usize = 1216;
pub const DK_SEED_LEN: usize = 32;
pub const KEM_CT_LEN: usize = 1120;
pub const SHARED_SECRET_LEN: usize = 32;

pub const ENCRYPTED_SEED_LEN: usize = DK_SEED_LEN;
pub const SEED_TAG_LEN: usize = TAG_LEN;
pub const PASSWORD_BLOB_LEN: usize = ENCRYPTED_SEED_LEN + SEED_TAG_LEN + 29;

pub const FILE_DERIVATION_LABEL: &[u8] = b"asymcrypt file derivation v1";
pub const DK_WRAP_NONCE_LABEL: &[u8] = b"asymcrypt dk wrap nonce v1";

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

pub fn derive_file_secrets(
    shared_secret: &[u8; SHARED_SECRET_LEN],
    file_nonce: &[u8; FILE_NONCE_LEN],
) -> ([u8; CIPHER_KEY_LEN], [u8; NONCE_LEN]) {
    let mut full = hmac_sha256(shared_secret, &[FILE_DERIVATION_LABEL, file_nonce]);
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

pub fn kem_generate() -> ([u8; DK_SEED_LEN], [u8; EK_LEN]) {
    let (dk, ek) = XWingKem::generate_keypair();
    let mut seed = [0u8; DK_SEED_LEN];
    seed.copy_from_slice(dk.as_bytes());
    let mut ek_bytes = [0u8; EK_LEN];
    ek_bytes.copy_from_slice(ek.to_bytes().as_slice());
    (seed, ek_bytes)
}

pub fn kem_encapsulate(
    ek_bytes: &[u8; EK_LEN],
) -> anyhow::Result<([u8; KEM_CT_LEN], [u8; SHARED_SECRET_LEN])> {
    let ek = EncapsulationKey::new_from_slice(ek_bytes)
        .map_err(|_| anyhow::anyhow!("invalid X-Wing encapsulation key"))?;
    let (ct, ss) = ek.encapsulate();
    let mut ct_out = [0u8; KEM_CT_LEN];
    ct_out.copy_from_slice(ct.as_slice());
    let mut ss_out = [0u8; SHARED_SECRET_LEN];
    ss_out.copy_from_slice(ss.as_slice());
    Ok((ct_out, ss_out))
}

pub fn kem_decapsulate(seed: &[u8; DK_SEED_LEN], ct: &[u8; KEM_CT_LEN]) -> [u8; SHARED_SECRET_LEN] {
    let dk = DecapsulationKey::from(*seed);
    let ss = dk.decapsulate(ct.into());
    let mut ss_out = [0u8; SHARED_SECRET_LEN];
    ss_out.copy_from_slice(ss.as_slice());
    ss_out
}

fn dk_wrap_params(argon2_key: &[u8; SHARED_SECRET_LEN]) -> ([u8; CIPHER_KEY_LEN], [u8; NONCE_LEN]) {
    let mut wrap_key = [0u8; CIPHER_KEY_LEN];
    wrap_key.copy_from_slice(&argon2_key[..CIPHER_KEY_LEN]);
    let mut nonce_full = hmac_sha256(argon2_key, &[DK_WRAP_NONCE_LABEL]);
    let mut wrap_nonce = [0u8; NONCE_LEN];
    wrap_nonce.copy_from_slice(&nonce_full[..NONCE_LEN]);
    nonce_full.zeroize();
    (wrap_key, wrap_nonce)
}

pub fn wrap_dk_seed(
    argon2_key: &[u8; SHARED_SECRET_LEN],
    seed: &[u8; DK_SEED_LEN],
) -> ([u8; ENCRYPTED_SEED_LEN], [u8; SEED_TAG_LEN]) {
    let (wrap_key, wrap_nonce) = dk_wrap_params(argon2_key);
    let mut ct = [0u8; ENCRYPTED_SEED_LEN];
    ct.copy_from_slice(seed);
    let tag = Aegis128X2::<TAG_LEN>::new(&wrap_key, &wrap_nonce).encrypt_in_place(&mut ct, b"");
    (ct, tag)
}

pub fn unwrap_dk_seed(
    argon2_key: &[u8; SHARED_SECRET_LEN],
    encrypted_seed: &[u8; ENCRYPTED_SEED_LEN],
    seed_tag: &[u8; SEED_TAG_LEN],
) -> Result<[u8; DK_SEED_LEN], aegis::Error> {
    let (wrap_key, wrap_nonce) = dk_wrap_params(argon2_key);
    let mut seed = [0u8; DK_SEED_LEN];
    seed.copy_from_slice(encrypted_seed);
    Aegis128X2::<TAG_LEN>::new(&wrap_key, &wrap_nonce)
        .decrypt_in_place(&mut seed, seed_tag, b"")?;
    Ok(seed)
}

pub fn encrypt_chunk_in_place(
    key: &[u8; CIPHER_KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    buf: &mut [u8],
    ad: &[u8],
) -> [u8; TAG_LEN] {
    Aegis128X2::<TAG_LEN>::new(key, nonce).encrypt_in_place(buf, ad)
}

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
    fn derive_file_secrets_is_deterministic() {
        let k = [0x42u8; SHARED_SECRET_LEN];
        let fnz = [0x9eu8; FILE_NONCE_LEN];
        let a = derive_file_secrets(&k, &fnz);
        let b = derive_file_secrets(&k, &fnz);
        assert_eq!(a, b);
    }

    #[test]
    fn derive_file_secrets_depends_on_each_input() {
        let k1 = [1u8; SHARED_SECRET_LEN];
        let k2 = [2u8; SHARED_SECRET_LEN];
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
        let k = [0u8; SHARED_SECRET_LEN];
        let fnz = [0u8; FILE_NONCE_LEN];
        let (file_key, base_nonce) = derive_file_secrets(&k, &fnz);
        assert_ne!(file_key, base_nonce);
    }

    #[test]
    fn derive_file_secrets_known_vector() {
        let k = [0u8; SHARED_SECRET_LEN];
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
    fn kem_round_trip() {
        let (seed, ek) = kem_generate();
        let (ct, ss_enc) = kem_encapsulate(&ek).unwrap();
        let ss_dec = kem_decapsulate(&seed, &ct);
        assert_eq!(ss_enc, ss_dec);
    }

    #[test]
    fn kem_wrong_seed_produces_different_shared_secret() {
        let (_seed, ek) = kem_generate();
        let (seed2, _) = kem_generate();
        let (ct, ss_enc) = kem_encapsulate(&ek).unwrap();
        let ss_dec = kem_decapsulate(&seed2, &ct);
        assert_ne!(ss_enc, ss_dec);
    }

    #[test]
    fn wrap_unwrap_dk_seed_round_trip() {
        let key = [0xabu8; SHARED_SECRET_LEN];
        let seed = [0x42u8; DK_SEED_LEN];
        let (ct, tag) = wrap_dk_seed(&key, &seed);
        let recovered = unwrap_dk_seed(&key, &ct, &tag).unwrap();
        assert_eq!(recovered, seed);
    }

    #[test]
    fn unwrap_dk_seed_wrong_key_fails() {
        let key = [0xabu8; SHARED_SECRET_LEN];
        let seed = [0x42u8; DK_SEED_LEN];
        let (ct, tag) = wrap_dk_seed(&key, &seed);
        let wrong_key = [0xcdu8; SHARED_SECRET_LEN];
        assert!(unwrap_dk_seed(&wrong_key, &ct, &tag).is_err());
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
