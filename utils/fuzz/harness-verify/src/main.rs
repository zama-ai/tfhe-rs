//! Harness that deserializes and verify the zk proof.
//!
//! The goal is to find bugs in the zk verification code.

use tfhe::core_crypto::prelude::*;
use tfhe::integer::ciphertext::IntegerProvenCompactCiphertextListConformanceParams;
use tfhe::safe_serialization::safe_deserialize_conformant;
use tfhe::{CompactPublicKey, ProvenCompactCiphertextList};

use fuzz_utils::{ExecEndCause, INPUT_MAX_SIZE, harness_main};

fn handle_input(
    input: &[u8],
    conformance_params: &IntegerProvenCompactCiphertextListConformanceParams,
    crs: &CompactPkeCrs,
    public_key: &CompactPublicKey,
) -> ExecEndCause {
    let Ok(ct_list) = safe_deserialize_conformant::<ProvenCompactCiphertextList>(
        input,
        INPUT_MAX_SIZE,
        conformance_params,
    ) else {
        return ExecEndCause::SafeDeserializationFailed;
    };

    match ct_list.verify(crs, public_key, b"fuzz") {
        ZkVerificationOutcome::Valid => ExecEndCause::ExecSuccess,
        ZkVerificationOutcome::Invalid => ExecEndCause::ZkVerificationFailed,
    }
}

fn main() {
    harness_main(handle_input);
}
