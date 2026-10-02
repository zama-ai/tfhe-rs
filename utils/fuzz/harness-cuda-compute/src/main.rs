use tfhe::ProvenCompactCiphertextList;
use tfhe::safe_serialization::safe_deserialize_conformant;

use fuzz_utils::{ExecEndCause, GpuFuzzContext, INPUT_MAX_SIZE, harness_cuda_main, use_list};

fn handle_input(input: &[u8], ctx: &GpuFuzzContext) -> ExecEndCause {
    let Ok(ct_list) = safe_deserialize_conformant::<ProvenCompactCiphertextList>(
        input,
        INPUT_MAX_SIZE,
        &ctx.conformance_params,
    ) else {
        return ExecEndCause::SafeDeserializationFailed;
    };

    let Ok(exp) = ct_list.expand_without_verification() else {
        return ExecEndCause::ExpandFailed;
    };

    use_list(&exp)
}

fn main() {
    harness_cuda_main(handle_input)
}
