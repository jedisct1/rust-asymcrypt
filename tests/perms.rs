#![cfg(unix)]

use asymcrypt::cli::EncryptArgs;
use asymcrypt::format::DEFAULT_CHUNK_SIZE;
use asymcrypt::pipeline::{run_encrypt, run_init};
use std::fs;
use std::os::unix::fs::PermissionsExt;

mod common;
use common::{password_init, random_init, with_password};

#[test]
fn ek_file_skips_permission_check() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("k.key");
    let recovery = dir.path().join("rec.key");
    run_init(random_init(key.clone(), recovery)).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();

    let plain = dir.path().join("p");
    fs::write(&plain, b"x").unwrap();

    run_encrypt(EncryptArgs {
        key_file: key,
        input: Some(plain),
        output: Some(dir.path().join("p.enc")),
        chunk_size: DEFAULT_CHUNK_SIZE,
        force: false,
        insecure_perms: false,
    })
    .expect("public encapsulation key should not require 0600 permissions");
}

#[test]
fn composite_key_rejects_insecure_permissions() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("k.key");
    with_password("test", || {
        run_init(password_init(key.clone())).unwrap();
    });
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
    let err = res.expect_err("encrypt with group-readable composite key must fail");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("insecure permissions"),
        "expected permission error, got: {msg}"
    );
}

#[test]
fn composite_key_insecure_perms_flag_overrides() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("k.key");
    with_password("test", || {
        run_init(password_init(key.clone())).unwrap();
    });
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();

    let plain = dir.path().join("p");
    fs::write(&plain, b"x").unwrap();

    run_encrypt(EncryptArgs {
        key_file: key,
        input: Some(plain),
        output: Some(dir.path().join("p.enc")),
        chunk_size: DEFAULT_CHUNK_SIZE,
        force: false,
        insecure_perms: true,
    })
    .expect("--insecure-perms should let a 0644 composite key encrypt");
}
