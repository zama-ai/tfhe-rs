use crate::utils::Environment;
use crate::{cmd, ENV_TARGET_NATIVE};
use std::collections::HashMap;
use std::io::Error;

lazy_static! {
    static ref ENV_TARGET_SIMD: Environment = {
        let mut env = HashMap::new();
        env.insert(
            "RUSTFLAGS",
            "-Ctarget-feature=+aes,+rdseed,+sse2,+avx,+avx2",
        );
        env
    };
    static ref ENV_DOCTEST: Environment = {
        let mut env = HashMap::new();
        env.insert("RUSTDOCFLAGS", "-Zunstable-options --no-run");
        env
    };
    static ref ENV_DOCTEST_SIMD: Environment = {
        let mut env = HashMap::new();
        env.insert("RUSTDOCFLAGS", "-Zunstable-options --no-run");
        env.insert(
            "RUSTFLAGS",
            "-Ctarget-feature=+aes,+rdseed,+sse2,+avx,+avx2",
        );
        env
    };
    static ref ENV_DOCTEST_NATIVE: Environment = {
        let mut env = HashMap::new();
        env.insert("RUSTDOCFLAGS", "-Zunstable-options --no-run");
        env.insert("RUSTFLAGS", "-Ctarget-cpu=native");
        env
    };
}

pub mod debug {
    use super::*;

    pub fn crates() -> Result<(), Error> {
        cmd!("cargo build --all-features")
    }

    pub fn benches() -> Result<(), Error> {
        cmd!("cargo build --benches")
    }

    pub fn tests() -> Result<(), Error> {
        cmd!("cargo test --no-run --all-features")
    }

    pub fn doctests() -> Result<(), Error> {
        cmd!(<ENV_DOCTEST> "cargo +nightly test --doc --all-features")
    }
}

pub mod release {
    use super::*;

    pub fn crates() -> Result<(), Error> {
        cmd!("cargo build --release --all-features")
    }

    pub fn benches() -> Result<(), Error> {
        cmd!("cargo build --release --benches")
    }

    pub fn tests() -> Result<(), Error> {
        cmd!("cargo test --release --no-run --all-features")
    }

    pub fn doctests() -> Result<(), Error> {
        cmd!(<ENV_DOCTEST> "cargo +nightly test --release --doc --all-features")
    }
}

pub mod simd {
    use super::*;

    pub fn crates() -> Result<(), Error> {
        if cfg!(target_os = "linux") {
            cmd!(<ENV_TARGET_SIMD> "cargo build --release --all-features")
        } else if cfg!(target_os = "macos") {
            cmd!(<ENV_TARGET_NATIVE> "cargo build --release --all-features")
        } else {
            unreachable!()
        }
    }

    pub fn benches() -> Result<(), Error> {
        if cfg!(target_os = "linux") {
            cmd!(<ENV_TARGET_SIMD> "cargo build --release --benches")
        } else if cfg!(target_os = "macos") {
            cmd!(<ENV_TARGET_NATIVE> "cargo build --release --benches")
        } else {
            unreachable!()
        }
    }

    pub fn tests() -> Result<(), Error> {
        if cfg!(target_os = "linux") {
            cmd!(<ENV_TARGET_SIMD> "cargo test --release --no-run --all-features")
        } else if cfg!(target_os = "macos") {
            cmd!(<ENV_TARGET_NATIVE> "cargo test --release --no-run --all-features")
        } else {
            unreachable!()
        }
    }

    pub fn doctests() -> Result<(), Error> {
        if cfg!(target_os = "linux") {
            cmd!(<ENV_DOCTEST_SIMD> "cargo +nightly test --release --doc --all-features")
        } else if cfg!(target_os = "macos") {
            cmd!(<ENV_DOCTEST_NATIVE> "cargo +nightly test --release --doc --all-features")
        } else {
            unreachable!()
        }
    }
}
