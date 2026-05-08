use asymcrypt::cli::{DecryptArgs, EncryptArgs, InitArgs};
use asymcrypt::crypto::{DK_SEED_LEN, EK_LEN, PASSWORD_BLOB_LEN};
use asymcrypt::key::{
    KEY_TYPE_COMPOSITE, KEY_TYPE_DK_SEED, KEY_TYPE_EK, ParsedKeyFile, parse_key_file,
};
use asymcrypt::pipeline::{run_decrypt, run_encrypt, run_init};
use std::fs;
use std::path::PathBuf;

mod common;
use common::{password_init, password_init_hex, random_init, random_init_hex, with_password};

fn encrypt_args(key_file: PathBuf, input: PathBuf, output: PathBuf) -> EncryptArgs {
    EncryptArgs {
        key_file,
        input: Some(input),
        output: Some(output),
        chunk_size: 1024,
        force: false,
        insecure_perms: false,
    }
}

fn decrypt_args_keyfile(key_file: PathBuf, input: PathBuf, output: PathBuf) -> DecryptArgs {
    DecryptArgs {
        key_file: Some(key_file),
        password: false,
        input: Some(input),
        output: Some(output),
        force: false,
        insecure_perms: false,
    }
}

fn decrypt_args_password(input: PathBuf, output: PathBuf) -> DecryptArgs {
    DecryptArgs {
        key_file: None,
        password: true,
        input: Some(input),
        output: Some(output),
        force: false,
        insecure_perms: false,
    }
}

#[test]
fn random_mode_writes_both_files() {
    let dir = tempfile::tempdir().unwrap();
    let device = dir.path().join("device.key");
    let recovery = dir.path().join("recovery.key");
    run_init(random_init(device.clone(), recovery.clone())).unwrap();

    let dev_bytes = fs::read(&device).unwrap();
    let rec_bytes = fs::read(&recovery).unwrap();

    assert_eq!(dev_bytes.len(), 1 + EK_LEN);
    assert_eq!(rec_bytes.len(), 1 + DK_SEED_LEN);
    assert_eq!(dev_bytes[0], KEY_TYPE_EK);
    assert_eq!(rec_bytes[0], KEY_TYPE_DK_SEED);

    let dev = parse_key_file(&dev_bytes).unwrap();
    let rec = parse_key_file(&rec_bytes).unwrap();
    assert!(dev.is_public());
    assert!(!rec.is_public());
}

#[test]
fn random_mode_hex() {
    let dir = tempfile::tempdir().unwrap();
    let device = dir.path().join("device.key");
    let recovery = dir.path().join("recovery.key");
    run_init(random_init_hex(device.clone(), recovery.clone())).unwrap();

    for path in [&device, &recovery] {
        let bytes = fs::read(path).unwrap();
        let trimmed: Vec<u8> = bytes
            .iter()
            .copied()
            .filter(|b| !b.is_ascii_whitespace())
            .collect();
        assert!(
            trimmed.iter().all(|b| b.is_ascii_hexdigit()),
            "expected hex body in {}",
            path.display()
        );
    }

    let dev = parse_key_file(&fs::read(&device).unwrap()).unwrap();
    let rec = parse_key_file(&fs::read(&recovery).unwrap()).unwrap();
    assert!(dev.is_public());
    assert!(!rec.is_public());
}

#[cfg(unix)]
#[test]
fn recovery_key_is_mode_0600() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let device = dir.path().join("device.key");
    let recovery = dir.path().join("recovery.key");
    run_init(random_init(device.clone(), recovery.clone())).unwrap();
    let rec_mode = fs::metadata(&recovery).unwrap().permissions().mode() & 0o777;
    assert_eq!(rec_mode, 0o600, "recovery key has mode {:o}", rec_mode);
}

#[cfg(unix)]
#[test]
fn device_key_is_mode_0644() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let device = dir.path().join("device.key");
    let recovery = dir.path().join("recovery.key");
    run_init(random_init(device.clone(), recovery.clone())).unwrap();
    let dev_mode = fs::metadata(&device).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        dev_mode, 0o644,
        "public encapsulation key should be world-readable, got {:o}",
        dev_mode
    );
}

#[test]
fn password_mode_writes_only_device() {
    let dir = tempfile::tempdir().unwrap();
    let device = dir.path().join("device.key");
    with_password("hunter2", || {
        run_init(password_init(device.clone())).unwrap();
    });
    let bytes = fs::read(&device).unwrap();
    assert_eq!(bytes.len(), 1 + EK_LEN + PASSWORD_BLOB_LEN);
    assert_eq!(bytes[0], KEY_TYPE_COMPOSITE);
    let parsed = parse_key_file(&bytes).unwrap();
    assert!(!parsed.is_public());
}

#[test]
fn password_mode_hex_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let device = dir.path().join("device.key");
    with_password("hunter2", || {
        run_init(password_init_hex(device.clone())).unwrap();
    });
    let bytes = fs::read(&device).unwrap();
    let trimmed: Vec<u8> = bytes
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    assert!(trimmed.iter().all(|b| b.is_ascii_hexdigit()));
    let parsed = parse_key_file(&bytes).unwrap();
    assert!(!parsed.is_public());
}

#[test]
fn random_mode_refuses_to_overwrite_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let device = dir.path().join("device.key");
    let recovery = dir.path().join("recovery.key");
    fs::write(&recovery, b"do not clobber me").unwrap();
    let res = run_init(random_init(device.clone(), recovery.clone()));
    assert!(res.is_err());
    assert_eq!(fs::read(&recovery).unwrap(), b"do not clobber me");
    assert!(!device.exists(), "device must not be created on failure");
}

#[test]
fn random_mode_refuses_to_overwrite_device() {
    let dir = tempfile::tempdir().unwrap();
    let device = dir.path().join("device.key");
    let recovery = dir.path().join("recovery.key");
    fs::write(&device, b"do not clobber me").unwrap();
    let res = run_init(random_init(device.clone(), recovery.clone()));
    assert!(res.is_err());
    assert_eq!(fs::read(&device).unwrap(), b"do not clobber me");
    assert!(
        !recovery.exists(),
        "recovery must not be created when device already exists"
    );
}

#[test]
fn password_mode_refuses_to_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let device = dir.path().join("device.key");
    fs::write(&device, b"do not clobber me").unwrap();
    let res = with_password("hunter2", || run_init(password_init(device.clone())));
    assert!(res.is_err());
    assert_eq!(fs::read(&device).unwrap(), b"do not clobber me");
}

#[test]
fn equal_paths_rejected_before_io() {
    let dir = tempfile::tempdir().unwrap();
    let same = dir.path().join("k.key");
    let res = run_init(random_init(same.clone(), same.clone()));
    assert!(res.is_err());
    assert!(!same.exists());
}

#[test]
fn missing_parent_directory_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let recovery = dir.path().join("recovery.key");
    let device = dir.path().join("no-such-dir").join("device.key");
    let res = run_init(random_init(device.clone(), recovery.clone()));
    assert!(res.is_err());
    assert!(!recovery.exists(), "recovery must not be written");
    assert!(!device.exists(), "device must not be written");
}

#[test]
fn runtime_validation_random_requires_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let device = dir.path().join("device.key");
    let args = InitArgs {
        out: device.clone(),
        recovery_out: None,
        password: false,
        hex: false,
        argon2_mem: None,
        argon2_iters: None,
        argon2_lanes: None,
    };
    let err = run_init(args).expect_err("missing --recovery-out must fail");
    assert!(format!("{err:#}").contains("recovery-out"));
    assert!(!device.exists());
}

#[test]
fn runtime_validation_password_rejects_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let device = dir.path().join("device.key");
    let recovery = dir.path().join("recovery.key");
    let args = InitArgs {
        out: device.clone(),
        recovery_out: Some(recovery.clone()),
        password: true,
        hex: false,
        argon2_mem: Some(8 * 1024),
        argon2_iters: Some(1),
        argon2_lanes: Some(1),
    };
    let res = with_password("hunter2", || run_init(args));
    let err = res.expect_err("--recovery-out with --password must fail");
    assert!(format!("{err:#}").contains("recovery-out"));
    assert!(!device.exists());
    assert!(!recovery.exists());
}

#[test]
fn round_trip_recovers_with_offline_key() {
    let dir = tempfile::tempdir().unwrap();
    let device = dir.path().join("device.key");
    let recovery = dir.path().join("recovery.key");
    run_init(random_init(device.clone(), recovery.clone())).unwrap();

    let plain = dir.path().join("plain.txt");
    let cipher = dir.path().join("plain.asym");
    let recovered = dir.path().join("plain.out");
    fs::write(&plain, b"hello x-wing").unwrap();

    run_encrypt(encrypt_args(device, plain, cipher.clone())).unwrap();
    run_decrypt(decrypt_args_keyfile(recovery, cipher, recovered.clone())).unwrap();
    assert_eq!(fs::read(&recovered).unwrap(), b"hello x-wing");
}

#[test]
fn encrypt_rejects_recovery_key() {
    let dir = tempfile::tempdir().unwrap();
    let device = dir.path().join("device.key");
    let recovery = dir.path().join("recovery.key");
    run_init(random_init(device.clone(), recovery.clone())).unwrap();

    let dev_before = fs::read(&device).unwrap();
    let rec_before = fs::read(&recovery).unwrap();

    let plain = dir.path().join("plain.txt");
    let cipher = dir.path().join("plain.asym");
    fs::write(&plain, b"should not encrypt").unwrap();

    let res = run_encrypt(encrypt_args(recovery.clone(), plain, cipher.clone()));
    let err = res.expect_err("encrypt with recovery key must fail");
    assert!(format!("{err:#}").contains("decapsulation seed"));

    assert_eq!(fs::read(&device).unwrap(), dev_before);
    assert_eq!(fs::read(&recovery).unwrap(), rec_before);
    assert!(!cipher.exists(), "no ciphertext should have been written");
}

#[test]
fn decrypt_rejects_ek_file() {
    let dir = tempfile::tempdir().unwrap();
    let device = dir.path().join("device.key");
    let recovery = dir.path().join("recovery.key");
    run_init(random_init(device.clone(), recovery.clone())).unwrap();

    let plain = dir.path().join("plain.txt");
    let cipher = dir.path().join("plain.asym");
    let out = dir.path().join("out.bin");
    fs::write(&plain, b"hi").unwrap();
    run_encrypt(encrypt_args(device.clone(), plain, cipher.clone())).unwrap();

    let res = run_decrypt(decrypt_args_keyfile(device, cipher, out.clone()));
    let err = res.expect_err("decrypt with public ek must fail");
    assert!(format!("{err:#}").contains("encapsulation key"));
    assert!(!out.exists());
}

#[test]
fn password_mode_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let device = dir.path().join("device.key");
    let plain = dir.path().join("plain.txt");
    let cipher = dir.path().join("plain.asym");
    let recovered = dir.path().join("plain.out");
    fs::write(&plain, b"password mode payload").unwrap();

    with_password("hunter2", || {
        run_init(password_init(device.clone())).unwrap();
        run_encrypt(encrypt_args(device.clone(), plain.clone(), cipher.clone())).unwrap();
        run_decrypt(decrypt_args_password(cipher.clone(), recovered.clone())).unwrap();
        assert_eq!(fs::read(&recovered).unwrap(), b"password mode payload");
    });
}

#[test]
fn decrypt_password_on_public_key_mode_fails_before_prompting() {
    let dir = tempfile::tempdir().unwrap();
    let device = dir.path().join("device.key");
    let recovery = dir.path().join("recovery.key");
    run_init(random_init(device.clone(), recovery)).unwrap();

    let plain = dir.path().join("plain.txt");
    let cipher = dir.path().join("plain.asym");
    fs::write(&plain, b"public key mode").unwrap();
    run_encrypt(encrypt_args(device, plain, cipher.clone())).unwrap();

    let out = dir.path().join("out.bin");
    let res = run_decrypt(decrypt_args_password(cipher, out.clone()));
    let err = res.expect_err("password decrypt on non-password ciphertext must fail");
    assert!(
        format!("{err:#}").contains("not encrypted in password mode"),
        "expected early error about non-password mode, got: {err:#}"
    );
    assert!(!out.exists());
}

#[test]
fn argon2_zero_iters_rejected_before_password_prompt() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("k.key");
    let mut args = password_init(key.clone());
    args.argon2_iters = Some(0);
    let err = run_init(args).expect_err("zero iterations must be rejected");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("argon2-iters"),
        "expected argon2-iters error, got: {msg}"
    );
    assert!(!key.exists(), "no key file should be written on failure");
}

#[test]
fn argon2_flags_without_password_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let device = dir.path().join("k.key");
    let recovery = dir.path().join("r.key");

    for set in [
        |a: &mut InitArgs| a.argon2_mem = Some(65536),
        |a: &mut InitArgs| a.argon2_iters = Some(3),
        |a: &mut InitArgs| a.argon2_lanes = Some(2),
    ] {
        let mut args = random_init(device.clone(), recovery.clone());
        set(&mut args);
        let err = run_init(args).expect_err("argon2 flag without --password must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("argon2") && msg.contains("password"),
            "expected runtime rejection, got: {msg}"
        );
        assert!(!device.exists());
        assert!(!recovery.exists());
    }
}

#[test]
fn kem_keypair_is_consistent() {
    let dir = tempfile::tempdir().unwrap();
    let device = dir.path().join("device.key");
    let recovery = dir.path().join("recovery.key");
    run_init(random_init(device.clone(), recovery.clone())).unwrap();

    let dev_parsed = parse_key_file(&fs::read(&device).unwrap()).unwrap();
    let rec_parsed = parse_key_file(&fs::read(&recovery).unwrap()).unwrap();

    let ek_bytes = match dev_parsed {
        ParsedKeyFile::EncapsulationKey { ek_bytes, .. } => ek_bytes,
        _ => panic!("expected EncapsulationKey"),
    };
    let seed = match rec_parsed {
        ParsedKeyFile::DecapsulationSeed { seed, .. } => seed,
        _ => panic!("expected DecapsulationSeed"),
    };

    let (ct, ss_enc) = asymcrypt::crypto::kem_encapsulate(&ek_bytes).unwrap();
    let ss_dec = asymcrypt::crypto::kem_decapsulate(&seed, &ct);
    assert_eq!(
        ss_enc, ss_dec,
        "KEM keypair written by init must be consistent"
    );
}
