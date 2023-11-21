use super::utils::*;
use std::os::raw::c_int;

#[no_mangle]
pub unsafe extern "C" fn core_crypto_lwe_multi_bit_bootstrapping_key_element_size(
    input_lwe_sk_dim: usize,
    output_glwe_sk_dim: usize,
    output_glwe_sk_poly_size: usize,
    lwe_multi_bit_level_count: usize,
    lwe_multi_bit_grouping_factor: usize,
    result: *mut usize,
) -> c_int {
    catch_panic(|| {
        use crate::core_crypto::prelude::*;

        let result = get_mut_checked(result).unwrap();

        let input_lwe_sk_dim = LweDimension(input_lwe_sk_dim);

        let output_glwe_sk_dim = GlweDimension(output_glwe_sk_dim);
        let output_glwe_sk_poly_size = PolynomialSize(output_glwe_sk_poly_size);

        let lwe_multi_bit_level_count = DecompositionLevelCount(lwe_multi_bit_level_count);
        let lwe_multi_bit_grouping_factor = LweBskGroupingFactor(lwe_multi_bit_grouping_factor);

        *result = lwe_multi_bit_bootstrap_key_size(
            input_lwe_sk_dim,
            output_glwe_sk_dim.to_glwe_size(),
            output_glwe_sk_poly_size,
            lwe_multi_bit_level_count,
            lwe_multi_bit_grouping_factor,
        )
        .unwrap();
    })
}

#[no_mangle]
pub unsafe extern "C" fn core_crypto_par_generate_lwe_multi_bit_bootstrapping_key(
    input_lwe_sk_ptr: *const u64,
    input_lwe_sk_dim: usize,
    output_glwe_sk_ptr: *const u64,
    output_glwe_sk_dim: usize,
    output_glwe_sk_poly_size: usize,
    lwe_multi_bit_ptr: *mut u64,
    lwe_multi_bit_base_log: usize,
    lwe_multi_bit_level_count: usize,
    lwe_multi_bit_grouping_factor: usize,
    glwe_encryption_std_dev: f64,
    seed_low_bytes: u64,
    seed_high_bytes: u64,
) -> c_int {
    catch_panic(|| {
        use crate::core_crypto::commons::generators::DeterministicSeeder;
        use crate::core_crypto::commons::math::random::Seed;
        use crate::core_crypto::prelude::*;

        let input_lwe_sk_slice = std::slice::from_raw_parts(input_lwe_sk_ptr, input_lwe_sk_dim);
        let input_lwe_sk = LweSecretKey::from_container(input_lwe_sk_slice);

        let output_glwe_sk_dim = GlweDimension(output_glwe_sk_dim);
        let output_glwe_sk_poly_size = PolynomialSize(output_glwe_sk_poly_size);
        let output_glwe_sk_size =
            glwe_ciphertext_mask_size(output_glwe_sk_dim, output_glwe_sk_poly_size);
        let output_glwe_sk_slice =
            std::slice::from_raw_parts(output_glwe_sk_ptr, output_glwe_sk_size);
        let output_glwe_sk =
            GlweSecretKey::from_container(output_glwe_sk_slice, output_glwe_sk_poly_size);

        let seed_low_bytes: u128 = seed_low_bytes.into();
        let seed_high_bytes: u128 = seed_high_bytes.into();
        let seed = (seed_high_bytes << 64) | seed_low_bytes;

        let mut deterministic_seeder =
            DeterministicSeeder::<ActivatedRandomGenerator>::new(Seed(seed));
        let mut encryption_random_generator =
            EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(
                deterministic_seeder.seed(),
                &mut deterministic_seeder,
            );

        let lwe_multi_bit_base_log = DecompositionBaseLog(lwe_multi_bit_base_log);
        let lwe_multi_bit_level_count = DecompositionLevelCount(lwe_multi_bit_level_count);
        let lwe_multi_bit_grouping_factor = LweBskGroupingFactor(lwe_multi_bit_grouping_factor);

        let lwe_multi_bit_slice_len = {
            let bsk = LweMultiBitBootstrapKeyOwned::new(
                0u64,
                output_glwe_sk.glwe_dimension().to_glwe_size(),
                output_glwe_sk.polynomial_size(),
                lwe_multi_bit_base_log,
                lwe_multi_bit_level_count,
                input_lwe_sk.lwe_dimension(),
                lwe_multi_bit_grouping_factor,
                CiphertextModulus::new_native(),
            );
            bsk.into_container().len()
        };

        let lwe_multi_bit_slice =
            std::slice::from_raw_parts_mut(lwe_multi_bit_ptr, lwe_multi_bit_slice_len);

        let mut bsk = LweMultiBitBootstrapKey::from_container(
            lwe_multi_bit_slice,
            output_glwe_sk.glwe_dimension().to_glwe_size(),
            output_glwe_sk.polynomial_size(),
            lwe_multi_bit_base_log,
            lwe_multi_bit_level_count,
            lwe_multi_bit_grouping_factor,
            CiphertextModulus::new_native(),
        );

        let glwe_encryption_std_dev = StandardDev(glwe_encryption_std_dev);

        par_generate_lwe_multi_bit_bootstrap_key(
            &input_lwe_sk,
            &output_glwe_sk,
            &mut bsk,
            glwe_encryption_std_dev,
            &mut encryption_random_generator,
        );
    })
}
