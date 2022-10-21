use crate::utils::Environment;
use crate::{cmd, ENV_TARGET_NATIVE};
use std::collections::HashMap;
use std::io::Error;

lazy_static! {
    static ref ENV_COVERAGE: Environment = {
        let mut env = HashMap::new();
        env.insert("CARGO_INCREMENTAL", "0");
        env.insert("RUSTFLAGS", "-Zprofile -Ccodegen-units=1 -Cinline-threshold=0 -Clink-dead-code -Coverflow-checks=off -Cpanic=abort -Zpanic_abort_tests");
        env.insert("RUSTDOCFLAGS", "-Zprofile -Ccodegen-units=1 -Cinline-threshold=0 -Clink-dead-code -Coverflow-checks=off -Cpanic=abort -Zpanic_abort_tests");
        env
    };
}

pub fn toplevel() -> Result<(), Error> {
    cmd!(<ENV_TARGET_NATIVE> "cargo test --release --no-fail-fast --all-features -p concrete")
}

pub fn boolean() -> Result<(), Error> {
    cmd!(<ENV_TARGET_NATIVE> "cargo test --release --no-fail-fast --all-features -p concrete-boolean")
}

pub fn crates() -> Result<(), Error> {
    toplevel()?;
    boolean()?;
    Ok(())
}

pub fn cov_crates() -> Result<(), Error> {
    cmd!(<ENV_COVERAGE> "cargo +nightly test --release --no-fail-fast --all-features")
}
