use anyhow::Result;
use clap::Parser;

use asymcrypt::cli::{Cli, Command};
use asymcrypt::pipeline::{run_decrypt, run_encrypt, run_init};

fn main() {
    let exit_code = match real_main() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("asymcrypt: {e:#}");
            1
        }
    };
    std::process::exit(exit_code);
}

fn real_main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init(a) => run_init(a),
        Command::Encrypt(a) => run_encrypt(a),
        Command::Decrypt(a) => run_decrypt(a),
    }
}
