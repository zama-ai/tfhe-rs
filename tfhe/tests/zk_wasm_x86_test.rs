//! Test compatibility between x86_64 and wasm proofs
//!
//! - Generate a crs and public key from rust
//! - Load them in js, encrypt and prove some ciphertexts
//! - Load the proven ciphertexts in rust and verify the proof

#![cfg(feature = "zk-pok")]
#![cfg(feature = "integer")]

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::Command;
use tfhe::safe_serialization::{safe_deserialize, safe_serialize};
use tfhe::shortint::parameters::compact_public_key_only::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use tfhe::shortint::parameters::key_switching::p_fail_2_minus_64::ks_pbs::V0_11_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;
use tfhe::zk::CompactPkeCrs;
use tfhe::{ClientKey, CompactPublicKey, ConfigBuilder, ProvenCompactCiphertextList};

const SIZE_LIMIT: u64 = 1024 * 1024 * 1024;
const METADATA: [u8; 6] = [b'w', b'a', b's', b'm', b'6', b'4'];

fn gen_key_and_crs() -> (CompactPublicKey, CompactPkeCrs) {
    println!("Generating keys");
    let config =
        crate::ConfigBuilder::with_custom_parameters(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64)
            .use_dedicated_compact_public_key_parameters((
                V0_11_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
                V0_11_PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
            ))
            .build();

    let client_key = ClientKey::generate(config);
    let pub_key = CompactPublicKey::new(&client_key);

    println!("Generating crs");
    let crs = CompactPkeCrs::from_config(config, 16).unwrap();

    (pub_key, crs)
}

fn gen_proven_ct_in_wasm(path: &Path) {
    println!("Generating proven ciphertext in wasm");
    let mut child = Command::new("node")
        .arg("index.js")
        .current_dir(path)
        .spawn()
        .expect("Failed to run node script");

    let exit_status = child.wait().unwrap();
    if let Some(exit_code) = exit_status.code() {
        if exit_code == 0 {
            return;
        }
    }

    panic!("node script returned a non-0 code.");
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

#[test]
fn test_proof_compat_with_wasm() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let mut test_path = PathBuf::from(manifest_dir);
    test_path.push("tests");
    test_path.push("zk_wasm_x86_test");

    let (pub_key, crs) = gen_key_and_crs();

    let mut f_pubkey = File::create(test_path.join("public_key.bin")).unwrap();
    safe_serialize(&pub_key, &mut f_pubkey, SIZE_LIMIT).unwrap();

    let mut f_crs = File::create(test_path.join("crs.bin")).unwrap();
    safe_serialize(&crs, &mut f_crs, SIZE_LIMIT).unwrap();

    gen_proven_ct_in_wasm(&test_path);

    let mut f_ct = File::open(test_path.join("proof.bin")).unwrap();
    let proven_ct: ProvenCompactCiphertextList = safe_deserialize(&mut f_ct, SIZE_LIMIT).unwrap();

    verify_proof(&pub_key, &crs, &proven_ct);
}
