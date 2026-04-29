#![cfg(unix)]

use asymcrypt::cli::EncryptArgs;
use asymcrypt::format::DEFAULT_CHUNK_SIZE;
use asymcrypt::pipeline::{run_encrypt, run_init};
use std::fs;
use std::os::unix::fs::PermissionsExt;

mod common;
use common::random_init;

#[test]
fn group_or_world_readable_key_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("k.key");
    let recovery = dir.path().join("rec.key");
    run_init(random_init(key.clone(), recovery)).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();

    let plain = dir.path().join("p");
    fs::write(&plain, b"x").unwrap();

    let res = run_encrypt(EncryptArgs {
        key_file: key.clone(),
        input: Some(plain.clone()),
        output: Some(dir.path().join("p.enc")),
        chunk_size: DEFAULT_CHUNK_SIZE,
        force: false,
        insecure_perms: false,
    });
    let err = res.expect_err("encrypt with group-readable key must fail");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("insecure permissions"),
        "expected permission error, got: {msg}"
    );

    // The key file must not have been advanced by the rejected attempt.
    let mode = fs::metadata(&key).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o644);
}

#[test]
fn insecure_perms_flag_overrides() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("k.key");
    let recovery = dir.path().join("rec.key");
    run_init(random_init(key.clone(), recovery)).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();

    let plain = dir.path().join("p");
    fs::write(&plain, b"x").unwrap();

    run_encrypt(EncryptArgs {
        key_file: key.clone(),
        input: Some(plain),
        output: Some(dir.path().join("p.enc")),
        chunk_size: DEFAULT_CHUNK_SIZE,
        force: false,
        insecure_perms: true,
    })
    .expect("--insecure-perms should let a 0644 key encrypt");

    // The rotation should preserve the (insecure) mode the user set.
    let mode = fs::metadata(&key).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o644,
        "key rotation should preserve original permissions"
    );
}
