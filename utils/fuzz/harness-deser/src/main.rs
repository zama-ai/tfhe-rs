//! Harness that only does deserialization and conformance.
//!
//! The goal is to be as fast as possible to explore the deserialization code, and cover the
//! ciphertext format to produce ciphertexts that can be reused by the other harnesses

use tfhe::integer::ciphertext::IntegerProvenCompactCiphertextListConformanceParams;
use tfhe::safe_serialization::safe_deserialize_conformant;
use tfhe::zk::CompactPkeCrs;
use tfhe::{CompactPublicKey, ProvenCompactCiphertextList};

use fuzz_utils::{ExecEndCause, INPUT_MAX_SIZE, harness_main};

fn handle_input(
    input: &[u8],
    conformance_params: &IntegerProvenCompactCiphertextListConformanceParams,
    _crs: &CompactPkeCrs,
    _public_key: &CompactPublicKey,
) -> ExecEndCause {
    match safe_deserialize_conformant::<ProvenCompactCiphertextList>(
        input,
        INPUT_MAX_SIZE,
        conformance_params,
    ) {
        Ok(_) => ExecEndCause::ExecSuccess,
        Err(_) => ExecEndCause::SafeDeserializationFailed,
    }
}

fn main() {
    harness_main(handle_input)
}
