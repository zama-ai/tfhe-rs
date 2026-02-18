use crate::core_crypto::prelude::CiphertextModulus;
use crate::integer::gpu::list_compression::server_keys::CudaDecompressionKey;
use crate::integer::gpu::server_key::CudaBootstrappingKey;
use crate::shortint::server_key::{
    generate_lookup_table_with_output_encoding, LookupTableOwned, LookupTableSize,
};
use crate::shortint::{CarryModulus, MessageModulus};

/// Test-only helper function to create a rescaling LUT for decompression tests.
/// This generates a lookup table that rescales values from effective compression moduli
/// to output moduli, which is needed for noise distribution testing in GPU operations.
pub fn create_rescaling_lut(
    decompression_key: &CudaDecompressionKey,
    ciphertext_modulus: CiphertextModulus<u64>,
    effective_compression_message_modulus: MessageModulus,
    effective_compression_carry_modulus: CarryModulus,
    output_message_modulus: MessageModulus,
    output_carry_modulus: CarryModulus,
) -> LookupTableOwned {
    let (out_glwe_size, out_polynomial_size) = match decompression_key.blind_rotate_key {
        CudaBootstrappingKey::Classic(ref bsk) => {
            (bsk.glwe_dimension.to_glwe_size(), bsk.polynomial_size)
        }
        CudaBootstrappingKey::MultiBit(ref bsk) => {
            (bsk.glwe_dimension.to_glwe_size(), bsk.polynomial_size)
        }
    };
    let lut_size = LookupTableSize::new(out_glwe_size, out_polynomial_size);

    generate_lookup_table_with_output_encoding(
        lut_size,
        ciphertext_modulus,
        // Input moduli are the effective compression ones
        effective_compression_message_modulus,
        effective_compression_carry_modulus,
        // Output moduli are directly the ones stored in the list
        output_message_modulus,
        output_carry_modulus,
        // Here we do not divide by message_modulus
        // Example: in the 2_2 case we are mapping a 2 bits message onto a 4 bits space, we
        // want to keep the original 2 bits value in the 4 bits space, so we apply the identity
        // and the encoding will rescale it for us.
        |x| x,
    )
}
