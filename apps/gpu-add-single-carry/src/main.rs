//! Drives the CUDA backend's `host_add_and_propagate_single_carry` with
//! `requested_flag = FLAG_CARRY` and `uses_carry = 1` on trivially encrypted inputs,
//! and checks both the sum and the carry out against clear arithmetic.

use tfhe::core_crypto::gpu::CudaStreams;
use tfhe::core_crypto::gpu::vec::GpuIndex;
use tfhe::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
use tfhe::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
use tfhe::integer::gpu::gen_keys_radix_gpu;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;

const NUM_BLOCKS: usize = 32;

fn main() {
    let streams = CudaStreams::new_single_gpu(GpuIndex::new(0));
    let (cks, sks) = gen_keys_radix_gpu(
        PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
        NUM_BLOCKS,
        &streams,
    );

    // With 2 message bits per block, 32 blocks hold 64-bit integers. The clear reference is
    // computed in u128 so that `modulus` (2^64) and the carry out stay representable.
    let bits_per_block = cks.parameters().message_modulus().0.ilog2() as usize;
    let modulus = 1u128 << (NUM_BLOCKS * bits_per_block);

    // (lhs, rhs, carry_in)
    let cases = [(32768u64, 32768u64, true)];

    for (lhs, rhs, carry_in) in cases {
        let d_lhs: CudaUnsignedRadixCiphertext =
            sks.create_trivial_radix(lhs, NUM_BLOCKS, &streams);
        let d_rhs: CudaUnsignedRadixCiphertext =
            sks.create_trivial_radix(rhs, NUM_BLOCKS, &streams);
        // A trivial 1-block radix of 0/1 has degree <= 1, which is what a CudaBooleanBlock needs.
        let d_carry_in = CudaBooleanBlock::from_cuda_radix_ciphertext(
            sks.create_trivial_radix::<u64, CudaUnsignedRadixCiphertext>(
                u64::from(carry_in),
                1,
                &streams,
            )
            .ciphertext,
        );

        let (d_sum, d_carry_out) = sks.unchecked_unsigned_add_with_input_carry_and_carry_flag(
            &d_lhs,
            &d_rhs,
            &d_carry_in,
            &streams,
        );

        let sum: u64 = cks.decrypt(&d_sum.to_radix_ciphertext(&streams));
        let carry_out = cks.decrypt_bool(&d_carry_out.to_boolean_block(&streams));

        let clear = u128::from(lhs) + u128::from(rhs) + u128::from(carry_in);
        let (expected_sum, expected_carry_out) = (clear % modulus, clear >= modulus);
        let sum = u128::from(sum);

        println!(
            "{lhs:>3} + {rhs:>3} + {} = {sum:>3} carry_out={carry_out} \
             (expected {expected_sum:>3} carry_out={expected_carry_out})",
            u8::from(carry_in)
        );
        assert_eq!(
            sum, expected_sum,
            "wrong sum for {lhs} + {rhs} + {carry_in}"
        );
        assert_eq!(
            carry_out, expected_carry_out,
            "wrong carry out for {lhs} + {rhs} + {carry_in}"
        );
    }

    println!("all cases passed");
}
