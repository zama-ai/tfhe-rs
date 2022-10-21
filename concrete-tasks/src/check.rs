use crate::cmd;
use crate::utils::Environment;
use std::collections::HashMap;
use std::io::Error;

lazy_static! {
    static ref ENV_DOC_KATEX: Environment = {
        let mut env = HashMap::new();
        env.insert("RUSTDOCFLAGS", "--html-in-header katex-header.html");
        env
    };
}

pub fn doc() -> Result<(), Error> {
    cmd!(<ENV_DOC_KATEX> "cargo +nightly doc --features=doc --no-deps")
}

pub fn clippy() -> Result<(), Error> {
    cmd!("cargo +nightly clippy --all-targets --all-features -- --no-deps")
}

pub fn fmt() -> Result<(), Error> {
    cmd!("cargo +nightly fmt --all -- --check")
}
