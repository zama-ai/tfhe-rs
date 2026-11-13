//! GPU fuzz harness that drives OPRF generation and trivial encryption for every
//! fhevm host-executor ciphertext type.
//!
//! The raw AFL input is interpreted as a stream of bytes to source scalars from
//! (see [`fuzz_utils::ScalarSource`]). For each supported type the harness invokes
//! `generate_oblivious_pseudo_random[_bounded]` and `try_encrypt_trivial`, then
//! compresses the batch to exercise the full output path.
//!
//! Unlike `harness-cuda-compute`, this harness takes no compact ciphertext list
//! input and therefore no ZK verification path — the corpus is pure entropy.

use tfhe::CompressedCiphertextListBuilder;

use fuzz_utils::{
    ExecEndCause, GpuFuzzContext, ScalarSource, generate_scalar_ops_gpu, harness_cuda_main,
};

fn handle_input(input: &[u8], _ctx: &GpuFuzzContext) -> ExecEndCause {
    let mut builder = CompressedCiphertextListBuilder::new();
    let mut source = ScalarSource::new(input);
    generate_scalar_ops_gpu(&mut builder, &mut source);

    if builder.build().is_err() {
        return ExecEndCause::CompressionFailed;
    }

    ExecEndCause::ExecSuccess
}

fn main() {
    harness_cuda_main(handle_input)
}
