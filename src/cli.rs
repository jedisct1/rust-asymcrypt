use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

use crate::format::{DEFAULT_CHUNK_SIZE, MAX_CHUNK_SIZE};

#[derive(Parser, Debug)]
#[command(
    name = "asymcrypt",
    about = "Encrypt streams with a key that cannot decrypt what it just wrote",
    version,
    arg_required_else_help = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Initialise a fresh key chain.
    ///
    /// By default, writes a random recovery key to `--recovery-out` (keep
    /// this offline) and the working key to `--out`. With `--password`,
    /// derives the recovery key from a prompted password and writes only
    /// `--out`.
    Init(InitArgs),
    /// Encrypt a stream using the current mutable key, then evolve it.
    Encrypt(EncryptArgs),
    /// Decrypt a stream by walking the key chain forward from a recovery key
    /// or password.
    Decrypt(DecryptArgs),
}

#[derive(Args, Debug)]
pub struct InitArgs {
    /// Path for the working key used by `encrypt`. Will not overwrite.
    #[arg(long, short = 'o')]
    pub out: PathBuf,
    /// Path for the offline recovery key. Required unless `--password` is set.
    #[arg(long = "recovery-out", short = 'r')]
    pub recovery_out: Option<PathBuf>,
    /// Derive the recovery key from a prompted password instead of random bytes.
    #[arg(long)]
    pub password: bool,
    /// Write key files as ASCII hex instead of raw bytes.
    #[arg(long)]
    pub hex: bool,
    /// Argon2id memory cost in KiB (requires `--password`).
    #[arg(long)]
    pub argon2_mem: Option<u32>,
    /// Argon2id iteration count (requires `--password`).
    #[arg(long)]
    pub argon2_iters: Option<u32>,
    /// Argon2id parallelism (requires `--password`).
    #[arg(long)]
    pub argon2_lanes: Option<u32>,
}

#[derive(Args, Debug)]
pub struct EncryptArgs {
    /// Path to the key file.
    #[arg(long, short = 'k')]
    pub key_file: PathBuf,
    /// Input file. Use `-` or omit for stdin.
    #[arg(long, short = 'i')]
    pub input: Option<PathBuf>,
    /// Output file. Use `-` or omit for stdout.
    #[arg(long, short = 'o')]
    pub output: Option<PathBuf>,
    /// Plaintext bytes per chunk.
    #[arg(long, default_value_t = DEFAULT_CHUNK_SIZE)]
    pub chunk_size: u32,
    /// Allow overwriting an existing output file.
    #[arg(long)]
    pub force: bool,
    /// Skip the group/world-readable permission check on the key file.
    #[arg(long)]
    pub insecure_perms: bool,
}

#[derive(Args, Debug)]
pub struct DecryptArgs {
    /// Original recovery key. Mutually exclusive with --password.
    #[arg(long, short = 'k', conflicts_with = "password")]
    pub key_file: Option<PathBuf>,
    /// Derive the original key by prompting for the password.
    #[arg(long)]
    pub password: bool,
    /// Input file. Use `-` or omit for stdin.
    #[arg(long, short = 'i')]
    pub input: Option<PathBuf>,
    /// Output file. Use `-` or omit for stdout.
    #[arg(long, short = 'o')]
    pub output: Option<PathBuf>,
    /// Maximum number of key-chain steps to try. 0 means "only the provided
    /// key".
    #[arg(long, default_value_t = 1_000_000u64)]
    pub max_key_steps: u64,
    /// Allow overwriting an existing output file.
    #[arg(long)]
    pub force: bool,
    /// Skip the group/world-readable permission check on the key file.
    #[arg(long)]
    pub insecure_perms: bool,
}

pub fn validate_chunk_size(n: u32) -> anyhow::Result<()> {
    if n == 0 || n > MAX_CHUNK_SIZE {
        anyhow::bail!("chunk size must be in 1..={}", MAX_CHUNK_SIZE);
    }
    Ok(())
}
