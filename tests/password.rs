use asymcrypt::cli::{DecryptArgs, EncryptArgs};
use asymcrypt::format::DEFAULT_CHUNK_SIZE;
use asymcrypt::pipeline::{run_decrypt, run_encrypt, run_init};
use std::fs;

mod common;
use common::{password_init, with_password};

#[test]
fn password_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("k.key");

    with_password("correct horse battery staple", || {
        run_init(password_init(key.clone())).unwrap();
    });

    let plain_path = dir.path().join("p");
    fs::write(&plain_path, b"top secret backup").unwrap();
    let ct = dir.path().join("p.enc");
    run_encrypt(EncryptArgs {
        key_file: key.clone(),
        input: Some(plain_path),
        output: Some(ct.clone()),
        chunk_size: DEFAULT_CHUNK_SIZE,
        force: false,
        insecure_perms: false,
    })
    .unwrap();

    let out = dir.path().join("p.dec");
    with_password("correct horse battery staple", || {
        run_decrypt(DecryptArgs {
            key_file: None,
            password: true,
            input: Some(ct.clone()),
            output: Some(out.clone()),
            max_key_steps: 8,
            force: true,
            insecure_perms: false,
        })
        .unwrap();
    });
    assert_eq!(fs::read(&out).unwrap(), b"top secret backup");
}

#[test]
fn wrong_password_fails() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("k.key");
    with_password("right one", || {
        run_init(password_init(key.clone())).unwrap();
    });
    let plain_path = dir.path().join("p");
    fs::write(&plain_path, b"x").unwrap();
    let ct = dir.path().join("p.enc");
    run_encrypt(EncryptArgs {
        key_file: key,
        input: Some(plain_path),
        output: Some(ct.clone()),
        chunk_size: DEFAULT_CHUNK_SIZE,
        force: false,
        insecure_perms: false,
    })
    .unwrap();
    let res = with_password("wrong one", || {
        run_decrypt(DecryptArgs {
            key_file: None,
            password: true,
            input: Some(ct),
            output: Some(dir.path().join("oops")),
            max_key_steps: 4,
            force: true,
            insecure_perms: false,
        })
    });
    assert!(res.is_err());
}
