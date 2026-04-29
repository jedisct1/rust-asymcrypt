#![allow(dead_code)]

use asymcrypt::cli::InitArgs;
use std::path::PathBuf;
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Run `f` with `ASYMCRYPT_PASSWORD` set, serialised against any other
/// caller in the same test binary. Touching the process environment is
/// inherently global, so we take an exclusive lock for the duration.
pub fn with_password<R>(pw: &str, f: impl FnOnce() -> R) -> R {
    let _g = ENV_LOCK.lock().unwrap();
    // SAFETY: serialised with ENV_LOCK to keep this single-threaded.
    unsafe { std::env::set_var("ASYMCRYPT_PASSWORD", pw) };
    let out = f();
    unsafe { std::env::remove_var("ASYMCRYPT_PASSWORD") };
    out
}

pub fn random_init(out: PathBuf, recovery_out: PathBuf) -> InitArgs {
    InitArgs {
        out,
        recovery_out: Some(recovery_out),
        password: false,
        hex: false,
        argon2_mem: None,
        argon2_iters: None,
        argon2_lanes: None,
    }
}

pub fn random_init_hex(out: PathBuf, recovery_out: PathBuf) -> InitArgs {
    InitArgs {
        out,
        recovery_out: Some(recovery_out),
        password: false,
        hex: true,
        argon2_mem: None,
        argon2_iters: None,
        argon2_lanes: None,
    }
}

pub fn password_init(out: PathBuf) -> InitArgs {
    InitArgs {
        out,
        recovery_out: None,
        password: true,
        hex: false,
        argon2_mem: Some(8 * 1024),
        argon2_iters: Some(1),
        argon2_lanes: Some(1),
    }
}

pub fn password_init_hex(out: PathBuf) -> InitArgs {
    InitArgs {
        hex: true,
        ..password_init(out)
    }
}
