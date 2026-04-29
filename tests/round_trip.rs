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
    cur: PathBuf,
    rec: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let cur = dir.path().join("cur.key");
        let rec = dir.path().join("rec.key");
        run_init(random_init(cur.clone(), rec.clone())).unwrap();
        Fixture { dir, cur, rec }
    }
}

fn encrypt_file(fix: &Fixture, plaintext: &[u8], out_name: &str) -> PathBuf {
    let plain_path = fix.dir.path().join(format!("{out_name}.plain"));
    fs::write(&plain_path, plaintext).unwrap();
    let ct_path = fix.dir.path().join(format!("{out_name}.enc"));
    run_encrypt(EncryptArgs {
        key_file: fix.cur.clone(),
        input: Some(plain_path),
        output: Some(ct_path.clone()),
        chunk_size: DEFAULT_CHUNK_SIZE,
        force: false,
        insecure_perms: false,
    })
    .unwrap();
    ct_path
}

fn decrypt_with(
    fix: &Fixture,
    key: &std::path::Path,
    ct: &std::path::Path,
    max_steps: u64,
) -> Vec<u8> {
    let dest = fix.dir.path().join("dec.out");
    let _ = fs::remove_file(&dest);
    run_decrypt(DecryptArgs {
        key_file: Some(key.to_path_buf()),
        password: false,
        input: Some(ct.to_path_buf()),
        output: Some(dest.clone()),
        max_key_steps: max_steps,
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
    let pt = decrypt_with(&fix, &fix.rec, &ct, 5);
    assert!(pt.is_empty());
}

#[test]
fn single_chunk_round_trip() {
    let fix = Fixture::new();
    let plain = b"a short payload";
    let ct = encrypt_file(&fix, plain, "short");
    assert_eq!(decrypt_with(&fix, &fix.rec, &ct, 5), plain);
}

#[test]
fn multi_chunk_round_trip() {
    let fix = Fixture::new();
    let plain: Vec<u8> = (0..2_500_000u32).map(|i| (i % 251) as u8).collect();
    let plain_path = fix.dir.path().join("big.plain");
    fs::write(&plain_path, &plain).unwrap();
    let ct_path = fix.dir.path().join("big.enc");
    run_encrypt(EncryptArgs {
        key_file: fix.cur.clone(),
        input: Some(plain_path),
        output: Some(ct_path.clone()),
        chunk_size: 256 * 1024,
        force: false,
        insecure_perms: false,
    })
    .unwrap();
    assert_eq!(decrypt_with(&fix, &fix.rec, &ct_path, 5), plain);
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
        key_file: fix.cur.clone(),
        input: Some(plain_path),
        output: Some(ct_path.clone()),
        chunk_size: chunk,
        force: false,
        insecure_perms: false,
    })
    .unwrap();
    assert_eq!(decrypt_with(&fix, &fix.rec, &ct_path, 5), plain);
}

#[test]
fn key_evolution_chain() {
    let fix = Fixture::new();
    let mut cts = Vec::new();
    let mut payloads = Vec::new();
    for i in 0..6 {
        let p = format!("payload {i}").into_bytes();
        let ct = encrypt_file(&fix, &p, &format!("chain{i}"));
        cts.push(ct);
        payloads.push(p);
    }
    for (ct, expected) in cts.iter().zip(payloads.iter()) {
        let got = decrypt_with(&fix, &fix.rec, ct, 50);
        assert_eq!(&got, expected);
    }
}

#[test]
fn current_key_cannot_decrypt_past_backup() {
    let fix = Fixture::new();
    let p1 = encrypt_file(&fix, b"first", "p1");
    let _p2 = encrypt_file(&fix, b"second", "p2");
    let res = run_decrypt(DecryptArgs {
        key_file: Some(fix.cur.clone()),
        password: false,
        input: Some(p1),
        output: Some(fix.dir.path().join("oops.out")),
        max_key_steps: 1_000,
        force: true,
        insecure_perms: false,
    });
    let err = res.expect_err("decrypt --key-file with a chain key must fail");
    assert!(format!("{err:#}").contains("chain"));
}

#[test]
fn wrong_recovery_key_fails() {
    let fix = Fixture::new();
    let ct = encrypt_file(&fix, b"hello", "wk");
    let other_cur = fix.dir.path().join("other.cur");
    let other_rec = fix.dir.path().join("other.rec");
    run_init(random_init(other_cur, other_rec.clone())).unwrap();
    let res = run_decrypt(DecryptArgs {
        key_file: Some(other_rec),
        password: false,
        input: Some(ct),
        output: Some(fix.dir.path().join("oops.out")),
        max_key_steps: 16,
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
        key_file: fix.cur.clone(),
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
        key_file: Some(fix.rec.clone()),
        password: false,
        input: Some(ct),
        output: Some(fix.dir.path().join("oops.out")),
        max_key_steps: 0,
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
        key_file: fix.cur.clone(),
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
        key_file: Some(fix.rec.clone()),
        password: false,
        input: Some(ct),
        output: Some(fix.dir.path().join("oops.out")),
        max_key_steps: 0,
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
        key_file: fix.cur.clone(),
        input: Some(plain_path),
        output: Some(ct.clone()),
        chunk_size: DEFAULT_CHUNK_SIZE,
        force: false,
        insecure_perms: false,
    });
    assert!(res.is_err());
    assert_eq!(fs::read(&ct).unwrap(), b"existing");
}

/// Failures *before* pre-rotation must not advance the chain. With the
/// pre-rotate-then-encrypt semantic, this only covers failures during input
/// or output setup — once `stage_key_replacement` commits, the device key
/// has already advanced regardless of what happens next.
#[test]
fn failure_before_pre_rotation_leaves_key_unchanged() {
    let fix = Fixture::new();
    let key_before = fs::read(&fix.cur).unwrap();
    let dst_dir = fix.dir.path().join("nope");
    let res = run_encrypt(EncryptArgs {
        key_file: fix.cur.clone(),
        input: None,
        output: Some(dst_dir.join("missing").join("oops.bin")),
        chunk_size: DEFAULT_CHUNK_SIZE,
        force: false,
        insecure_perms: false,
    });
    assert!(res.is_err());
    let key_after = fs::read(&fix.cur).unwrap();
    assert_eq!(
        key_before, key_after,
        "Output::open failure must precede pre-rotation"
    );
}

/// After one successful encryption the device's on-disk key must be
/// `evolve(K_0)`. This is the pre-rotation invariant: by the time the
/// process returns, no copy of `K_0` survives on disk anywhere on the
/// device, even though the backup itself was produced under `K_0`.
#[test]
fn pre_rotation_advances_disk_key_before_encryption_returns() {
    use asymcrypt::crypto::evolve_key;
    use asymcrypt::key::parse_key_file;

    let fix = Fixture::new();
    let k0_bytes = fs::read(&fix.cur).unwrap();
    let mut k0 = parse_key_file(&k0_bytes).unwrap().key;
    let mut expected = k0;
    evolve_key(&mut expected);

    let _ct = encrypt_file(&fix, b"some plaintext", "advance");

    let after_bytes = fs::read(&fix.cur).unwrap();
    let after = parse_key_file(&after_bytes).unwrap().key;
    assert_eq!(
        after, expected,
        "device key must equal evolve(K_0) after a successful encryption"
    );
    // Sanity: the backup was produced under K_0 and recovers under K_0.
    let recovered = decrypt_with(&fix, &fix.rec, &_ct, 4);
    assert_eq!(recovered, b"some plaintext");
    k0.iter_mut().for_each(|b| *b = 0);
    expected.iter_mut().for_each(|b| *b = 0);
}
