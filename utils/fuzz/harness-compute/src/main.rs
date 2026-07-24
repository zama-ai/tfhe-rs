//! Harness that deserializes and perform FHE computations
//!
//! The goal is to find bugs in FHE ops. This harness calls `expand_without_verification`, because
//! randomly producing a valid zk proof is extremely unlikely.

use tfhe::integer::ciphertext::IntegerProvenCompactCiphertextListConformanceParams;
use tfhe::safe_serialization::safe_deserialize_conformant;
use tfhe::zk::CompactPkeCrs;
use tfhe::{CompactPublicKey, ProvenCompactCiphertextList};

use fuzz_utils::{ExecEndCause, INPUT_MAX_SIZE, harness_main, use_list};

fn handle_input(
    input: &[u8],
    conformance_params: &IntegerProvenCompactCiphertextListConformanceParams,
    _crs: &CompactPkeCrs,
    _public_key: &CompactPublicKey,
) -> ExecEndCause {
    let Ok(ct_list) = safe_deserialize_conformant::<ProvenCompactCiphertextList>(
        input,
        INPUT_MAX_SIZE,
        conformance_params,
    ) else {
        return ExecEndCause::SafeDeserializationFailed;
    };

    let Ok(exp) = ct_list.expand_without_verification() else {
        return ExecEndCause::ExpandFailed;
    };

    use_list(&exp)
}

fn main() {
    harness_main(handle_input)
}
