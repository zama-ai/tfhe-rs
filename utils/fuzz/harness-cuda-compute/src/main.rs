use tfhe::ProvenCompactCiphertextList;
use tfhe::safe_serialization::safe_deserialize_conformant;
#[cfg(feature = "rerand")]
use tfhe::shortint::ciphertext::ReRandomizationContext;

use fuzz_utils::{ExecEndCause, GpuFuzzContext, INPUT_MAX_SIZE, harness_cuda_main, use_list};

fn handle_input(input: &[u8], ctx: &GpuFuzzContext) -> ExecEndCause {
    let Ok(ct_list) = safe_deserialize_conformant::<ProvenCompactCiphertextList>(
        input,
        INPUT_MAX_SIZE,
        &ctx.conformance_params,
    ) else {
        return ExecEndCause::SafeDeserializationFailed;
    };

    #[cfg(feature = "rerand")]
    let expand_result = {
        // Derive a deterministic seed from the input so AFL can replay crashes.
        let mut rerand_ctx = ReRandomizationContext::new(*b"FUZZ_Rrd", *b"FUZZ_Enc");
        rerand_ctx.add_bytes(input);
        let seed = rerand_ctx.finalize().next_seed();
        ct_list.re_randomize_and_expand_without_verification(&ctx.public_key, seed)
    };
    #[cfg(not(feature = "rerand"))]
    let expand_result = ct_list.expand_without_verification();

    let Ok(exp) = expand_result else {
        return ExecEndCause::ExpandFailed;
    };

    use_list(&exp)
}

fn main() {
    harness_cuda_main(handle_input)
}
