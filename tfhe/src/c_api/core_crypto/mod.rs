use super::utils::*;
use std::os::raw::c_int;

#[no_mangle]
pub unsafe extern "C" fn core_crypto_generate_binary_lwe_secret_key(
    output_lwe_sk_ptr: *mut u64,
    lwe_sk_dim: usize,
) -> c_int {
    catch_panic(|| {
        use crate::core_crypto::prelude::*;

        let mut seeder = new_seeder();
        let seeder = seeder.as_mut();
        // Create the LweSecretKey
        let output_lwe_sk_slice = std::slice::from_raw_parts_mut(output_lwe_sk_ptr, lwe_sk_dim);

        let mut lwe_sk = LweSecretKey::from_container(output_lwe_sk_slice);

        let mut secret_generator =
            SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
        generate_binary_lwe_secret_key(&mut lwe_sk, &mut secret_generator);
    })
}

#[no_mangle]
pub unsafe extern "C" fn core_crypto_lwe_encrypt(
    output_ct_ptr: *mut u64,
    pt: u64,
    lwe_sk_ptr: *const u64,
    lwe_sk_dim: usize,
    lwe_encryption_std_dev: f64,
) -> c_int {
    catch_panic(|| {
        use crate::core_crypto::prelude::*;

        let lwe_sk_slice = std::slice::from_raw_parts(lwe_sk_ptr, lwe_sk_dim);
        let lwe_sk = LweSecretKey::from_container(lwe_sk_slice);

        let mut seeder = new_seeder();
        let seeder = seeder.as_mut();

        let mut encryption_generator =
            EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

        let plaintext = Plaintext(pt);
        let output_ct = std::slice::from_raw_parts_mut(output_ct_ptr, lwe_sk_dim + 1);
        let mut ct = LweCiphertext::from_container(output_ct, CiphertextModulus::new_native());

        let lwe_encryption_std_dev = StandardDev(lwe_encryption_std_dev);

        encrypt_lwe_ciphertext(
            &lwe_sk,
            &mut ct,
            plaintext,
            lwe_encryption_std_dev,
            &mut encryption_generator,
        );
    })
}

#[no_mangle]
pub unsafe extern "C" fn core_crypto_lwe_decrypt(
    output_pt: *mut u64,
    input_ct_ptr: *const u64,
    lwe_sk_ptr: *const u64,
    lwe_sk_dim: usize,
) -> c_int {
    catch_panic(|| {
        use crate::core_crypto::prelude::*;

        let lwe_sk_slice = std::slice::from_raw_parts(lwe_sk_ptr, lwe_sk_dim);
        let lwe_sk = LweSecretKey::from_container(lwe_sk_slice);

        let input_ct = std::slice::from_raw_parts(input_ct_ptr, lwe_sk_dim + 1);
        let ct = LweCiphertext::from_container(input_ct, CiphertextModulus::new_native());

        let plaintext = decrypt_lwe_ciphertext(&lwe_sk, &ct);

        *output_pt = plaintext.0;
    })
}

#[no_mangle]
pub unsafe extern "C" fn core_crypto_par_generate_lwe_bootstrapping_key(
    output_bsk_ptr: *mut u64,
    bsk_base_log: usize,
    bsk_level_count: usize,
    input_lwe_sk_ptr: *const u64,
    input_lwe_sk_dim: usize,
    output_glwe_sk_ptr: *const u64,
    output_glwe_sk_dim: usize,
    output_glwe_sk_poly_size: usize,
    glwe_encryption_std_dev: f64,
) -> c_int {
    catch_panic(|| {
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

        let mut seeder = new_seeder();
        let seeder = seeder.as_mut();

        let mut encryption_random_generator =
            EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

        let lwe_base_log = DecompositionBaseLog(bsk_base_log);
        let lwe_level_count = DecompositionLevelCount(bsk_level_count);

        let lwe_slice_len = {
            let bsk = LweBootstrapKeyOwned::new(
                0u64,
                output_glwe_sk.glwe_dimension().to_glwe_size(),
                output_glwe_sk.polynomial_size(),
                lwe_base_log,
                lwe_level_count,
                input_lwe_sk.lwe_dimension(),
                CiphertextModulus::new_native(),
            );
            bsk.into_container().len()
        };

        let bsk_slice = std::slice::from_raw_parts_mut(output_bsk_ptr, lwe_slice_len);

        let mut bsk = LweBootstrapKey::from_container(
            bsk_slice,
            output_glwe_sk.glwe_dimension().to_glwe_size(),
            output_glwe_sk.polynomial_size(),
            lwe_base_log,
            lwe_level_count,
            CiphertextModulus::new_native(),
        );

        let glwe_encryption_std_dev = StandardDev(glwe_encryption_std_dev);

        par_generate_lwe_bootstrap_key(
            &input_lwe_sk,
            &output_glwe_sk,
            &mut bsk,
            glwe_encryption_std_dev,
            &mut encryption_random_generator,
        )
    })
}

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
) -> c_int {
    catch_panic(|| {
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

        let mut seeder = new_seeder();
        let seeder = seeder.as_mut();
        let mut encryption_random_generator =
            EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);

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
        )
    })
}
