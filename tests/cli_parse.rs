use asymcrypt::cli::{Cli, Command};
use clap::Parser;

fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
    Cli::try_parse_from(args.iter().copied())
}

#[test]
fn keygen_subcommand_is_gone() {
    let err = parse(&["asymcrypt", "keygen", "--out", "k"]).unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::InvalidSubcommand);
}

#[test]
fn init_requires_out() {
    let err = parse(&["asymcrypt", "init"]).unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
}

#[test]
fn init_random_mode_parses_without_recovery_out_at_clap_layer() {
    let cli = parse(&["asymcrypt", "init", "-o", "k"]).unwrap();
    let Command::Init(args) = cli.command else {
        panic!("expected Init");
    };
    assert!(!args.password);
    assert!(args.recovery_out.is_none());
}

#[test]
fn init_random_mode_parses_with_both_paths() {
    let cli = parse(&["asymcrypt", "init", "-o", "k", "-r", "r"]).unwrap();
    let Command::Init(args) = cli.command else {
        panic!("expected Init");
    };
    assert!(!args.password);
    assert!(!args.hex);
    assert_eq!(
        args.recovery_out.as_deref(),
        Some(std::path::Path::new("r"))
    );
    assert!(args.argon2_mem.is_none());
    assert!(args.argon2_iters.is_none());
    assert!(args.argon2_lanes.is_none());
}

#[test]
fn init_password_mode_parses_without_recovery_out() {
    let cli = parse(&["asymcrypt", "init", "--password", "-o", "k"]).unwrap();
    let Command::Init(args) = cli.command else {
        panic!("expected Init");
    };
    assert!(args.password);
    assert!(args.recovery_out.is_none());
}

#[test]
fn init_argon2_mem_with_password_parses() {
    let cli = parse(&[
        "asymcrypt",
        "init",
        "--argon2-mem",
        "65536",
        "--password",
        "-o",
        "k",
    ])
    .unwrap();
    let Command::Init(args) = cli.command else {
        panic!("expected Init");
    };
    assert!(args.password);
    assert_eq!(args.argon2_mem, Some(65536));
}

#[test]
fn init_old_key_file_flag_is_gone() {
    let err = parse(&["asymcrypt", "init", "--key-file", "k"]).unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
}

#[test]
fn init_hex_works_in_both_modes() {
    let cli = parse(&["asymcrypt", "init", "--hex", "-o", "k", "-r", "r"]).unwrap();
    let Command::Init(args) = cli.command else {
        panic!("expected Init");
    };
    assert!(args.hex);

    let cli = parse(&["asymcrypt", "init", "--password", "--hex", "-o", "k"]).unwrap();
    let Command::Init(args) = cli.command else {
        panic!("expected Init");
    };
    assert!(args.password);
    assert!(args.hex);
}
