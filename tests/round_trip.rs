use asymcrypt::cli::{DecryptArgs, EncryptArgs};
use asymcrypt::format::DEFAULT_CHUNK_SIZE;
use asymcrypt::pipeline::{run_decrypt, run_encrypt, run_init};
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

mod common;
use common::random_init;

struct Fixture {
    dir: TempDir,
    ek: PathBuf,
    dk: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let ek = dir.path().join("device.key");
        let dk = dir.path().join("recovery.key");
        run_init(random_init(ek.clone(), dk.clone())).unwrap();
        Fixture { dir, ek, dk }
    }
}

fn encrypt_file(fix: &Fixture, plaintext: &[u8], out_name: &str) -> PathBuf {
    let plain_path = fix.dir.path().join(format!("{out_name}.plain"));
    fs::write(&plain_path, plaintext).unwrap();
    let ct_path = fix.dir.path().join(format!("{out_name}.enc"));
    run_encrypt(EncryptArgs {
        key_file: fix.ek.clone(),
        input: Some(plain_path),
        output: Some(ct_path.clone()),
        chunk_size: DEFAULT_CHUNK_SIZE,
        force: false,
        insecure_perms: false,
    })
    .unwrap();
    ct_path
}

fn decrypt_with(fix: &Fixture, ct: &std::path::Path) -> Vec<u8> {
    let dest = fix.dir.path().join("dec.out");
    let _ = fs::remove_file(&dest);
    run_decrypt(DecryptArgs {
        key_file: Some(fix.dk.clone()),
        password: false,
        input: Some(ct.to_path_buf()),
        output: Some(dest.clone()),
        force: true,
        insecure_perms: false,
    })
    .unwrap();
    fs::read(&dest).unwrap()
}

#[test]
fn empty_round_trip() {
    let fix = Fixture::new();
    let ct = encrypt_file(&fix, b"", "empty");
    let pt = decrypt_with(&fix, &ct);
    assert!(pt.is_empty());
}

#[test]
fn single_chunk_round_trip() {
    let fix = Fixture::new();
    let plain = b"a short payload";
    let ct = encrypt_file(&fix, plain, "short");
    assert_eq!(decrypt_with(&fix, &ct), plain);
}

#[test]
fn multi_chunk_round_trip() {
    let fix = Fixture::new();
    let plain: Vec<u8> = (0..2_500_000u32).map(|i| (i % 251) as u8).collect();
    let plain_path = fix.dir.path().join("big.plain");
    fs::write(&plain_path, &plain).unwrap();
    let ct_path = fix.dir.path().join("big.enc");
    run_encrypt(EncryptArgs {
        key_file: fix.ek.clone(),
        input: Some(plain_path),
        output: Some(ct_path.clone()),
        chunk_size: 256 * 1024,
        force: false,
        insecure_perms: false,
    })
    .unwrap();
    assert_eq!(decrypt_with(&fix, &ct_path), plain);
}

#[test]
fn exact_chunk_boundary() {
    let fix = Fixture::new();
    let chunk = 4096u32;
    let plain = vec![0xa5u8; (chunk * 3) as usize];
    let plain_path = fix.dir.path().join("bound.plain");
    fs::write(&plain_path, &plain).unwrap();
    let ct_path = fix.dir.path().join("bound.enc");
    run_encrypt(EncryptArgs {
        key_file: fix.ek.clone(),
        input: Some(plain_path),
        output: Some(ct_path.clone()),
        chunk_size: chunk,
        force: false,
        insecure_perms: false,
    })
    .unwrap();
    assert_eq!(decrypt_with(&fix, &ct_path), plain);
}

#[test]
fn multiple_encryptions_all_recoverable() {
    let fix = Fixture::new();
    let mut cts = Vec::new();
    let mut payloads = Vec::new();
    for i in 0..6 {
        let p = format!("payload {i}").into_bytes();
        let ct = encrypt_file(&fix, &p, &format!("multi{i}"));
        cts.push(ct);
        payloads.push(p);
    }
    for (ct, expected) in cts.iter().zip(payloads.iter()) {
        let got = decrypt_with(&fix, ct);
        assert_eq!(&got, expected);
    }
}

#[test]
fn device_key_cannot_decrypt() {
    let fix = Fixture::new();
    let ct = encrypt_file(&fix, b"hello", "devfail");
    let res = run_decrypt(DecryptArgs {
        key_file: Some(fix.ek.clone()),
        password: false,
        input: Some(ct),
        output: Some(fix.dir.path().join("oops.out")),
        force: true,
        insecure_perms: false,
    });
    assert!(
        res.is_err(),
        "decrypting with the public encapsulation key must fail"
    );
}

#[test]
fn wrong_recovery_key_fails() {
    let fix = Fixture::new();
    let ct = encrypt_file(&fix, b"hello", "wk");
    let other_ek = fix.dir.path().join("other.ek");
    let other_dk = fix.dir.path().join("other.dk");
    run_init(random_init(other_ek, other_dk.clone())).unwrap();
    let res = run_decrypt(DecryptArgs {
        key_file: Some(other_dk),
        password: false,
        input: Some(ct),
        output: Some(fix.dir.path().join("oops.out")),
        force: true,
        insecure_perms: false,
    });
    assert!(res.is_err());
}

#[test]
fn tampered_chunk_fails() {
    let fix = Fixture::new();
    let plain = vec![0x42u8; 300_000];
    let plain_path = fix.dir.path().join("t.plain");
    fs::write(&plain_path, &plain).unwrap();
    let ct = fix.dir.path().join("t.enc");
    run_encrypt(EncryptArgs {
        key_file: fix.ek.clone(),
        input: Some(plain_path),
        output: Some(ct.clone()),
        chunk_size: 64 * 1024,
        force: false,
        insecure_perms: false,
    })
    .unwrap();
    let mut bytes = fs::read(&ct).unwrap();
    let len = bytes.len();
    bytes[len - 30] ^= 0xff;
    fs::write(&ct, &bytes).unwrap();
    let res = run_decrypt(DecryptArgs {
        key_file: Some(fix.dk.clone()),
        password: false,
        input: Some(ct),
        output: Some(fix.dir.path().join("oops.out")),
        force: true,
        insecure_perms: false,
    });
    assert!(res.is_err());
    assert!(
        !fix.dir.path().join("oops.out").exists(),
        "no output should be committed on auth failure"
    );
}

#[test]
fn truncated_stream_fails() {
    let fix = Fixture::new();
    let plain = vec![1u8; 200_000];
    let plain_path = fix.dir.path().join("trunc.plain");
    fs::write(&plain_path, &plain).unwrap();
    let ct = fix.dir.path().join("trunc.enc");
    run_encrypt(EncryptArgs {
        key_file: fix.ek.clone(),
        input: Some(plain_path),
        output: Some(ct.clone()),
        chunk_size: 64 * 1024,
        force: false,
        insecure_perms: false,
    })
    .unwrap();
    let bytes = fs::read(&ct).unwrap();
    let cut = &bytes[..bytes.len() - 30];
    fs::write(&ct, cut).unwrap();
    let res = run_decrypt(DecryptArgs {
        key_file: Some(fix.dk.clone()),
        password: false,
        input: Some(ct),
        output: Some(fix.dir.path().join("oops.out")),
        force: true,
        insecure_perms: false,
    });
    assert!(res.is_err());
}

#[test]
fn refuse_overwrite_without_force() {
    let fix = Fixture::new();
    let plain_path = fix.dir.path().join("o.plain");
    fs::write(&plain_path, b"x").unwrap();
    let ct = fix.dir.path().join("o.enc");
    fs::write(&ct, b"existing").unwrap();
    let res = run_encrypt(EncryptArgs {
        key_file: fix.ek.clone(),
        input: Some(plain_path),
        output: Some(ct.clone()),
        chunk_size: DEFAULT_CHUNK_SIZE,
        force: false,
        insecure_perms: false,
    });
    assert!(res.is_err());
    assert_eq!(fs::read(&ct).unwrap(), b"existing");
}

#[test]
fn device_key_not_modified_by_encrypt() {
    let fix = Fixture::new();
    let key_before = fs::read(&fix.ek).unwrap();
    let _ct = encrypt_file(&fix, b"some plaintext", "nomod");
    let key_after = fs::read(&fix.ek).unwrap();
    assert_eq!(
        key_before, key_after,
        "device key file must not be modified by encryption (it's a public key)"
    );
}
