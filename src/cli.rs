use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

use crate::format::{DEFAULT_CHUNK_SIZE, MAX_CHUNK_SIZE};

#[derive(Parser, Debug)]
#[command(
    name = "asymcrypt",
    about = "Encrypt streams with a public key that cannot decrypt what it just wrote",
    version,
    arg_required_else_help = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Initialise an ML-KEM-768 key pair.
    ///
    /// By default, writes the public encapsulation key to `--out` (device)
    /// and the private decapsulation seed to `--recovery-out` (offline).
    /// With `--password`, derives a wrapping key from a prompted password,
    /// encrypts the seed into a composite key file at `--out`, and skips
    /// `--recovery-out`.
    Init(InitArgs),
    /// Encrypt a stream against the device's encapsulation key.
    Encrypt(EncryptArgs),
    /// Decrypt a stream using the offline decapsulation seed or a password.
    Decrypt(DecryptArgs),
}

#[derive(Args, Debug)]
pub struct InitArgs {
    /// Path for the device key used by `encrypt`. Will not overwrite.
    #[arg(long, short = 'o')]
    pub out: PathBuf,
    /// Path for the offline recovery key (decapsulation seed). Required
    /// unless `--password` is set.
    #[arg(long = "recovery-out", short = 'r')]
    pub recovery_out: Option<PathBuf>,
    /// Derive the wrapping key from a prompted password instead of writing
    /// a separate recovery file.
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
    /// Path to the key file (encapsulation key or composite).
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
    /// Offline decapsulation seed. Mutually exclusive with --password.
    #[arg(long, short = 'k', conflicts_with = "password")]
    pub key_file: Option<PathBuf>,
    /// Derive the decapsulation seed by prompting for the password.
    #[arg(long)]
    pub password: bool,
    /// Input file. Use `-` or omit for stdin.
    #[arg(long, short = 'i')]
    pub input: Option<PathBuf>,
    /// Output file. Use `-` or omit for stdout.
    #[arg(long, short = 'o')]
    pub output: Option<PathBuf>,
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
