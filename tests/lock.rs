use asymcrypt::cli::{DecryptArgs, EncryptArgs};
use asymcrypt::crypto::{MASTER_KEY_LEN, evolve_key};
use asymcrypt::key::parse_key_file;
use asymcrypt::pipeline::{run_decrypt, run_encrypt, run_init};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

mod common;
use common::random_init;

fn key_bytes(path: &std::path::Path) -> [u8; MASTER_KEY_LEN] {
    let raw = fs::read(path).unwrap();
    parse_key_file(&raw).unwrap().key
}

#[test]
fn concurrent_encryptions_serialize_on_lock_and_advance_chain_once_per_run() {
    let dir = tempfile::tempdir().unwrap();
    let cur = dir.path().join("cur.key");
    let recovery_path = dir.path().join("recovery.key");
    run_init(random_init(cur.clone(), recovery_path.clone())).unwrap();
    let initial_chain = key_bytes(&cur);

    const N: usize = 6;
    let cur = Arc::new(cur);
    let dirp = Arc::new(dir.path().to_path_buf());

    let mut handles = Vec::new();
    for i in 0..N {
        let cur = Arc::clone(&cur);
        let dirp = Arc::clone(&dirp);
        handles.push(thread::spawn(move || {
            let plain_path: PathBuf = dirp.join(format!("plain.{i}"));
            // Make each plaintext large enough that an unsynchronised second
            // encryption would overlap the first, so a missing lock would
            // either crash the test or duplicate a chain step.
            let plain: Vec<u8> = (0..512_000u32)
                .map(|x| ((x ^ i as u32) & 0xff) as u8)
                .collect();
            fs::write(&plain_path, &plain).unwrap();
            let ct_path: PathBuf = dirp.join(format!("ct.{i}"));
            run_encrypt(EncryptArgs {
                key_file: (*cur).clone(),
                input: Some(plain_path),
                output: Some(ct_path.clone()),
                chunk_size: 64 * 1024,
                force: false,
                insecure_perms: false,
            })
            .unwrap();
            (i, plain, ct_path)
        }));
    }
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    // After N successful encryptions the key file must have advanced exactly
    // N chain steps. If two encryptions had overlapped under the same key the
    // file would only have moved once, or worse, two backups would share a
    // chain step.
    let mut expected = initial_chain;
    for _ in 0..N {
        evolve_key(&mut expected);
    }
    let actual = key_bytes(&cur);
    assert_eq!(
        actual, expected,
        "key file must advance exactly N steps after N serialized encryptions"
    );

    // Every backup must round-trip with the original recovery key, walking
    // the chain forward.
    for (i, plain, ct) in results {
        let out = dirp.join(format!("out.{i}"));
        run_decrypt(DecryptArgs {
            key_file: Some(recovery_path.clone()),
            password: false,
            input: Some(ct),
            output: Some(out.clone()),
            max_key_steps: N as u64,
            force: true,
            insecure_perms: false,
        })
        .unwrap();
        assert_eq!(fs::read(&out).unwrap(), plain);
    }
}
