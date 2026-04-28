//! Test compatibility between x86_64 and wasm proofs, in two stages:
//! - `gen_zk_wasm_fixtures` writes the crs + public key (`crs.bin`,
//!   `public_key.bin`) consumed by the wasm `fixtureEncryptProveTest`.
//! - `verify_zk_wasm_proof` reloads them + the browser-produced `proof.bin` and
//!   verifies the proof on x86_64.

#![cfg(feature = "zk-pok")]
#![cfg(feature = "integer")]

use std::fs::File;
use std::path::PathBuf;
use tfhe::safe_serialization::{safe_deserialize, safe_serialize};
use tfhe::shortint::parameters::*;
use tfhe::zk::CompactPkeCrs;
use tfhe::{ClientKey, CompactPublicKey, ConfigBuilder, ProvenCompactCiphertextList};

const SIZE_LIMIT: u64 = 1024 * 1024 * 1024;
const METADATA: [u8; 6] = *b"wasm64";

/// Directory holding the fixtures (`public_key.bin`, `crs.bin`) and the
/// browser-produced `proof.bin`.
fn fixtures_dir() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("zk_wasm_x86_test");
    path
}

fn gen_key_and_crs() -> (CompactPublicKey, CompactPkeCrs) {
    println!("Generating keys");
    let config =
        crate::ConfigBuilder::with_custom_parameters(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
            .use_dedicated_compact_public_key_parameters((
                PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            ))
            .build();

    let client_key = ClientKey::generate(config);
    let pub_key = CompactPublicKey::new(&client_key);

    println!("Generating crs");
    let crs = CompactPkeCrs::from_config(config, 16).unwrap();

    (pub_key, crs)
}

fn verify_proof(
    public_key: &CompactPublicKey,
    crs: &CompactPkeCrs,
    proven_ct: &ProvenCompactCiphertextList,
) {
    println!("Verifying proof");
    match proven_ct.verify(crs, public_key, &METADATA) {
        tfhe::zk::ZkVerificationOutcome::Valid => {
            println!("proof verification succeeded");
        }
        tfhe::zk::ZkVerificationOutcome::Invalid => {
            panic!("proof verification failed!!!")
        }
    }
}

/// Stage 1: generate the public key + crs fixtures consumed by the wasm test.
///
/// Run on its own with:
/// `cargo test --test zk_wasm_x86_test -- --ignored --exact gen_zk_wasm_fixtures`
///
/// `#[ignore]` so a plain `cargo test` sweep doesn't run the two interdependent
/// stages out of order; they must be invoked explicitly (gen, then the wasm
/// step, then verify) — see `make test_zk_wasm_x86_compat`.
#[test]
#[ignore = "run explicitly via `make gen_zk_wasm_fixtures`; depends on the wasm step"]
fn gen_zk_wasm_fixtures() {
    let dir = fixtures_dir();
    // The directory only holds gitignored artifacts, so it may be absent in a
    // fresh checkout.
    std::fs::create_dir_all(&dir).unwrap();

    let (pub_key, crs) = gen_key_and_crs();

    let mut f_pubkey = File::create(dir.join("public_key.bin")).unwrap();
    safe_serialize(&pub_key, &mut f_pubkey, SIZE_LIMIT).unwrap();

    let mut f_crs = File::create(dir.join("crs.bin")).unwrap();
    safe_serialize(&crs, &mut f_crs, SIZE_LIMIT).unwrap();

    println!("Fixtures written to {}", dir.display());
}

/// Stage 2: reload the fixtures + the browser-produced proof and verify it.
///
/// Expects `gen_zk_wasm_fixtures` to have run and the wasm/selenium step to
/// have produced `proof.bin`. Run on its own with:
/// `cargo test --test zk_wasm_x86_test -- --ignored --exact verify_zk_wasm_proof`
#[test]
#[ignore = "run explicitly via `make verify_zk_wasm_proof` after the wasm step produced proof.bin"]
fn verify_zk_wasm_proof() {
    let dir = fixtures_dir();

    let mut f_pubkey = File::open(dir.join("public_key.bin")).expect(
        "public_key.bin missing — run `cargo test --test zk_wasm_x86_test -- --exact \
         gen_zk_wasm_fixtures` first",
    );
    let pub_key: CompactPublicKey = safe_deserialize(&mut f_pubkey, SIZE_LIMIT).unwrap();

    let mut f_crs = File::open(dir.join("crs.bin")).expect("crs.bin missing");
    let crs: CompactPkeCrs = safe_deserialize(&mut f_crs, SIZE_LIMIT).unwrap();

    let mut f_ct = File::open(dir.join("proof.bin")).expect(
        "proof.bin missing — it is produced by the wasm `fixtureEncryptProveTest` run via \
         `ci/webdriver.py --capture-key proof_b64 --capture-out .../proof.bin`",
    );
    let proven_ct: ProvenCompactCiphertextList = safe_deserialize(&mut f_ct, SIZE_LIMIT)
        .expect("proof.bin is malformed — re-run the wasm capture step that produces it");

    verify_proof(&pub_key, &crs, &proven_ct);
}
