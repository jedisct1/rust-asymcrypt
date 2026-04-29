use asymcrypt::cli::{DecryptArgs, EncryptArgs, InitArgs};
use asymcrypt::crypto::{MASTER_KEY_LEN, evolve_key};
use asymcrypt::format::ARGON2_METADATA_LEN;
use asymcrypt::key::{
    KEY_TYPE_COMPOSITE_V1, KEY_TYPE_PLAIN_V1, KEY_TYPE_RECOVERY_V1, KeyRole, parse_key_file,
};
use asymcrypt::pipeline::{run_decrypt, run_encrypt, run_init};
use std::fs;
use std::path::PathBuf;

mod common;
use common::{password_init, password_init_hex, random_init, random_init_hex, with_password};

fn read_master(bytes: &[u8]) -> [u8; MASTER_KEY_LEN] {
    parse_key_file(bytes).unwrap().key
}

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

fn decrypt_args_keyfile(
    key_file: PathBuf,
    input: PathBuf,
    output: PathBuf,
    max_steps: u64,
) -> DecryptArgs {
    DecryptArgs {
        key_file: Some(key_file),
        password: false,
        input: Some(input),
        output: Some(output),
        max_key_steps: max_steps,
        force: false,
        insecure_perms: false,
    }
}

fn decrypt_args_password(input: PathBuf, output: PathBuf, max_steps: u64) -> DecryptArgs {
    DecryptArgs {
        key_file: None,
        password: true,
        input: Some(input),
        output: Some(output),
        max_key_steps: max_steps,
        force: false,
        insecure_perms: false,
    }
}

#[test]
fn random_mode_writes_both_files_with_chain_invariant() {
    let dir = tempfile::tempdir().unwrap();
    let current = dir.path().join("current.key");
    let recovery = dir.path().join("recovery.key");
    run_init(random_init(current.clone(), recovery.clone())).unwrap();

    let cur_bytes = fs::read(&current).unwrap();
    let rec_bytes = fs::read(&recovery).unwrap();

    assert_eq!(cur_bytes.len(), 1 + MASTER_KEY_LEN);
    assert_eq!(rec_bytes.len(), 1 + MASTER_KEY_LEN);
    assert_eq!(cur_bytes[0], KEY_TYPE_PLAIN_V1);
    assert_eq!(rec_bytes[0], KEY_TYPE_RECOVERY_V1);

    let cur = parse_key_file(&cur_bytes).unwrap();
    let rec = parse_key_file(&rec_bytes).unwrap();
    assert_eq!(cur.role, KeyRole::Chain);
    assert_eq!(rec.role, KeyRole::Recovery);
    assert!(cur.kdf.is_none());
    assert!(rec.kdf.is_none());
    assert_ne!(cur.key, rec.key);

    let mut evolved = rec.key;
    evolve_key(&mut evolved);
    assert_eq!(evolved, cur.key, "current must equal evolve(recovery)");
}

#[test]
fn random_mode_hex_chain_invariant() {
    let dir = tempfile::tempdir().unwrap();
    let current = dir.path().join("current.key");
    let recovery = dir.path().join("recovery.key");
    run_init(random_init_hex(current.clone(), recovery.clone())).unwrap();

    for path in [&current, &recovery] {
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

    let cur = parse_key_file(&fs::read(&current).unwrap()).unwrap();
    let rec = parse_key_file(&fs::read(&recovery).unwrap()).unwrap();
    assert_eq!(cur.role, KeyRole::Chain);
    assert_eq!(rec.role, KeyRole::Recovery);

    let mut evolved = rec.key;
    evolve_key(&mut evolved);
    assert_eq!(evolved, cur.key);
}

#[cfg(unix)]
#[test]
fn random_mode_files_are_mode_0600() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let current = dir.path().join("current.key");
    let recovery = dir.path().join("recovery.key");
    run_init(random_init(current.clone(), recovery.clone())).unwrap();
    for path in [&current, &recovery] {
        let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{} has mode {:o}", path.display(), mode);
    }
}

#[test]
fn password_mode_writes_only_current() {
    let dir = tempfile::tempdir().unwrap();
    let current = dir.path().join("current.key");
    with_password("hunter2", || {
        run_init(password_init(current.clone())).unwrap();
    });
    let bytes = fs::read(&current).unwrap();
    assert_eq!(bytes.len(), 1 + MASTER_KEY_LEN + ARGON2_METADATA_LEN);
    assert_eq!(bytes[0], KEY_TYPE_COMPOSITE_V1);
    let parsed = parse_key_file(&bytes).unwrap();
    assert_eq!(parsed.role, KeyRole::Chain);
    assert!(parsed.kdf.is_some());
}

#[test]
fn password_mode_hex_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let current = dir.path().join("current.key");
    with_password("hunter2", || {
        run_init(password_init_hex(current.clone())).unwrap();
    });
    let bytes = fs::read(&current).unwrap();
    let trimmed: Vec<u8> = bytes
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    assert!(trimmed.iter().all(|b| b.is_ascii_hexdigit()));
    let parsed = parse_key_file(&bytes).unwrap();
    assert!(parsed.kdf.is_some());
    assert_eq!(parsed.role, KeyRole::Chain);
}

#[test]
fn random_mode_refuses_to_overwrite_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let current = dir.path().join("current.key");
    let recovery = dir.path().join("recovery.key");
    fs::write(&recovery, b"do not clobber me").unwrap();
    let res = run_init(random_init(current.clone(), recovery.clone()));
    assert!(res.is_err());
    assert_eq!(fs::read(&recovery).unwrap(), b"do not clobber me");
    assert!(!current.exists(), "current must not be created on failure");
}

#[test]
fn random_mode_refuses_to_overwrite_current() {
    let dir = tempfile::tempdir().unwrap();
    let current = dir.path().join("current.key");
    let recovery = dir.path().join("recovery.key");
    fs::write(&current, b"do not clobber me").unwrap();
    let res = run_init(random_init(current.clone(), recovery.clone()));
    assert!(res.is_err());
    assert_eq!(fs::read(&current).unwrap(), b"do not clobber me");
    assert!(
        !recovery.exists(),
        "recovery must not be created when current already exists"
    );
}

#[test]
fn password_mode_refuses_to_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let current = dir.path().join("current.key");
    fs::write(&current, b"do not clobber me").unwrap();
    let res = with_password("hunter2", || run_init(password_init(current.clone())));
    assert!(res.is_err());
    assert_eq!(fs::read(&current).unwrap(), b"do not clobber me");
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
    let current = dir.path().join("no-such-dir").join("current.key");
    let res = run_init(random_init(current.clone(), recovery.clone()));
    assert!(res.is_err());
    assert!(!recovery.exists(), "recovery must not be written");
    assert!(!current.exists(), "current must not be written");
}

#[test]
fn runtime_validation_random_requires_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let current = dir.path().join("current.key");
    let args = InitArgs {
        out: current.clone(),
        recovery_out: None,
        password: false,
        hex: false,
        argon2_mem: None,
        argon2_iters: None,
        argon2_lanes: None,
    };
    let err = run_init(args).expect_err("missing --recovery-out must fail");
    assert!(format!("{err:#}").contains("recovery-out"));
    assert!(!current.exists());
}

#[test]
fn runtime_validation_password_rejects_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let current = dir.path().join("current.key");
    let recovery = dir.path().join("recovery.key");
    let args = InitArgs {
        out: current.clone(),
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
    assert!(!current.exists());
    assert!(!recovery.exists());
}

#[test]
fn round_trip_recovers_with_offline_key() {
    let dir = tempfile::tempdir().unwrap();
    let current = dir.path().join("current.key");
    let recovery = dir.path().join("recovery.key");
    run_init(random_init(current.clone(), recovery.clone())).unwrap();

    let plain = dir.path().join("plain.txt");
    let cipher = dir.path().join("plain.asym");
    let recovered = dir.path().join("plain.out");
    fs::write(&plain, b"hello two-file init").unwrap();

    run_encrypt(encrypt_args(current.clone(), plain.clone(), cipher.clone())).unwrap();
    run_decrypt(decrypt_args_keyfile(
        recovery.clone(),
        cipher.clone(),
        recovered.clone(),
        1_000,
    ))
    .unwrap();
    assert_eq!(fs::read(&recovered).unwrap(), b"hello two-file init");
}

#[test]
fn recovery_is_at_step_zero_current_at_step_one() {
    let dir = tempfile::tempdir().unwrap();
    let current = dir.path().join("current.key");
    let recovery = dir.path().join("recovery.key");
    run_init(random_init(current.clone(), recovery.clone())).unwrap();

    let plain = dir.path().join("plain.txt");
    let cipher = dir.path().join("plain.asym");
    let out = dir.path().join("out.bin");
    fs::write(&plain, b"x").unwrap();

    run_encrypt(encrypt_args(current.clone(), plain.clone(), cipher.clone())).unwrap();

    let res = run_decrypt(decrypt_args_keyfile(
        recovery.clone(),
        cipher.clone(),
        out.clone(),
        0,
    ));
    assert!(
        res.is_err(),
        "with --max-key-steps 0, recovery key must not match (proves recovery is at step 0)"
    );
}

#[test]
fn password_mode_current_is_one_step_past_k0() {
    let dir = tempfile::tempdir().unwrap();
    let current = dir.path().join("current.key");
    let plain = dir.path().join("plain.txt");
    let cipher = dir.path().join("plain.asym");
    let recovered = dir.path().join("plain.out");
    fs::write(&plain, b"password mode chain step").unwrap();

    with_password("hunter2", || {
        run_init(password_init(current.clone())).unwrap();
        run_encrypt(encrypt_args(current.clone(), plain.clone(), cipher.clone())).unwrap();
        run_decrypt(decrypt_args_password(
            cipher.clone(),
            recovered.clone(),
            1_000,
        ))
        .unwrap();
        assert_eq!(fs::read(&recovered).unwrap(), b"password mode chain step");

        let strict = dir.path().join("strict.out");
        let res = run_decrypt(decrypt_args_password(cipher.clone(), strict, 0));
        assert!(
            res.is_err(),
            "password-derived K_0 with --max-key-steps 0 must fail (current is K_1, not K_0)"
        );
    });
}

#[test]
fn encrypt_rejects_recovery_key() {
    let dir = tempfile::tempdir().unwrap();
    let current = dir.path().join("current.key");
    let recovery = dir.path().join("recovery.key");
    run_init(random_init(current.clone(), recovery.clone())).unwrap();

    let cur_before = fs::read(&current).unwrap();
    let rec_before = fs::read(&recovery).unwrap();

    let plain = dir.path().join("plain.txt");
    let cipher = dir.path().join("plain.asym");
    fs::write(&plain, b"should not encrypt").unwrap();

    let res = run_encrypt(encrypt_args(
        recovery.clone(),
        plain.clone(),
        cipher.clone(),
    ));
    let err = res.expect_err("encrypt with --key-file pointing at a recovery key must fail");
    assert!(format!("{err:#}").contains("recovery"));

    assert_eq!(fs::read(&current).unwrap(), cur_before, "current rotated");
    assert_eq!(fs::read(&recovery).unwrap(), rec_before, "recovery touched");
    assert!(!cipher.exists(), "no ciphertext should have been written");
}

#[test]
fn decrypt_rejects_chain_key() {
    let dir = tempfile::tempdir().unwrap();
    let current = dir.path().join("current.key");
    let recovery = dir.path().join("recovery.key");
    run_init(random_init(current.clone(), recovery.clone())).unwrap();

    let plain = dir.path().join("plain.txt");
    let cipher = dir.path().join("plain.asym");
    let out = dir.path().join("out.bin");
    fs::write(&plain, b"hi").unwrap();
    run_encrypt(encrypt_args(current.clone(), plain.clone(), cipher.clone())).unwrap();

    // After encrypt, current has rotated to K_2, recovery still K_0.
    let res = run_decrypt(decrypt_args_keyfile(
        current.clone(),
        cipher.clone(),
        out.clone(),
        1_000,
    ));
    let err = res.expect_err("decrypt --key-file with a chain key must fail");
    assert!(format!("{err:#}").contains("chain"));
    assert!(!out.exists());

    let _ = read_master(&fs::read(&recovery).unwrap());
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
    let current = dir.path().join("k.key");
    let recovery = dir.path().join("r.key");

    for set in [
        |a: &mut InitArgs| a.argon2_mem = Some(65536),
        |a: &mut InitArgs| a.argon2_iters = Some(3),
        |a: &mut InitArgs| a.argon2_lanes = Some(2),
    ] {
        let mut args = random_init(current.clone(), recovery.clone());
        set(&mut args);
        let err = run_init(args).expect_err("argon2 flag without --password must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("argon2") && msg.contains("password"),
            "expected runtime rejection, got: {msg}"
        );
        assert!(!current.exists());
        assert!(!recovery.exists());
    }
}
