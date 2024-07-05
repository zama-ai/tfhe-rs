use std::process::{exit, Command};

fn get_supported_rustc_version() -> &'static str {
    const TOOLCHAIN_FILE: &str = include_str!("../../cargo-tfhe-lints-inner/rust-toolchain.toml");

    TOOLCHAIN_FILE
        .lines()
        .find(|line| line.starts_with("channel"))
        .and_then(|line| {
            line.rsplit('=')
                .next()
                .unwrap()
                .trim()
                .strip_prefix('"')
                .unwrap()
                .strip_suffix('"')
        })
        .unwrap()
}

fn main() {
    let cargo_args = std::env::args().skip(2).collect::<Vec<_>>();
    let toolchain = format!("+{}", get_supported_rustc_version());

    if let Err(err) = Command::new("cargo")
        .arg(toolchain.as_str())
        .arg("tfhe-lints-inner")
        .args(&cargo_args)
        .spawn()
        .and_then(|mut child| child.wait())
    {
        eprintln!(
            "Command `cargo {toolchain} tfhe-lints-inner {}` failed: {err:?}",
            cargo_args.join(" "),
        );
        exit(1);
    }
}
