use super::*;

use std::iter;
use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;
use crate::core_crypto::gpu::lwe_keyswitch_key::CudaLweKeyswitchKey;
use crate::core_crypto::gpu::vec::{CudaVec, GpuIndex};
use crate::core_crypto::gpu::{cuda_keyswitch_lwe_ciphertext, CudaStreams};
use itertools::Itertools;

use crate::core_crypto::gpu::algorithms::cuda_wrapping_polynomial_mul_one_to_many;
use crate::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;

pub fn encryption_delta<Scalar: UnsignedInteger>(
    bits_reserved_for_computation: usize,
    ciphertext_modulus: CiphertextModulus<Scalar>,
) -> Scalar {
    let modulus_for_computations = Scalar::ONE << bits_reserved_for_computation;
    match ciphertext_modulus.kind() {
        CiphertextModulusKind::Native => {
            ((Scalar::ONE << (Scalar::BITS - 1)) / modulus_for_computations) << 1
        }
        CiphertextModulusKind::NonNativePowerOfTwo => {
            let custom_mod = ciphertext_modulus
                .get_custom_modulus_as_optional_scalar()
                .unwrap();
            custom_mod / modulus_for_computations
        }
        CiphertextModulusKind::Other => todo!("Only power of 2 moduli are supported"),
    }
}


pub fn decrypt_glwe<Scalar, InputCont, KeyCont>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    glwe: &GlweCiphertext<InputCont>,
    bits_reserved_for_computation: usize,
) -> Vec<Scalar>
where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    KeyCont: Container<Element = Scalar>,
{
    let mut decrypted = PlaintextList::new(Scalar::ZERO, PlaintextCount(glwe.polynomial_size().0));
    let mut decoded = vec![Scalar::ZERO; decrypted.plaintext_count().0];
    decrypt_glwe_ciphertext(glwe_secret_key, glwe, &mut decrypted);

    let ciphertext_modulus = glwe.ciphertext_modulus();
    let delta = encryption_delta(bits_reserved_for_computation, ciphertext_modulus);

    let decomposer = SignedDecomposer::new(
        DecompositionBaseLog(
            bits_reserved_for_computation
                + ciphertext_modulus
                    .get_power_of_two_scaling_to_native_torus()
                    .ilog2() as usize,
        ),
        DecompositionLevelCount(1),
    );

    let decryption_modulus = Scalar::ONE << bits_reserved_for_computation;

    for (decoded_value, decrypted_value) in decoded.iter_mut().zip(decrypted.iter()) {
        *decoded_value =
            (decomposer.closest_representable(*decrypted_value.0) / delta) % decryption_modulus;

        if *decoded_value >= decryption_modulus / Scalar::TWO {
            *decoded_value = (decryption_modulus - *decoded_value).wrapping_neg();
        }
    }

    decoded
}

fn glwe_dot_product_with_clear<Scalar: UnsignedTorus + CastFrom<usize>>(
    params: ClassicTestParams<Scalar>,
) {
    let encryption_glwe_dimension = GlweDimension(1);
    let glwe_size = encryption_glwe_dimension.to_glwe_size();
    let polynomial_size = PolynomialSize(2048);
    let ciphertext_modulus = CiphertextModulus::new_native();
    let glwe_noise_distribution =
        Gaussian::from_dispersion_parameter(StandardDev(0.00000000000000029403601535432533), 0.0);

    let bits_reserved_for_computation = 12;

    // This could be a method to generate a private key object
    let mut seeder = new_seeder();
    let seeder = seeder.as_mut();
    let mut secret_rng = SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());
    let mut encryption_generator =
        EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);

    let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
        encryption_glwe_dimension,
        polynomial_size,
        &mut secret_rng,
    );

    let mut glwe = GlweCiphertext::new(
        Scalar::ZERO,
        glwe_size,
        polynomial_size,
        ciphertext_modulus,
    );

    let delta = encryption_delta(bits_reserved_for_computation, ciphertext_modulus);

    let plaintext_list =
        PlaintextList::new(delta, PlaintextCount(glwe.polynomial_size().0));

    encrypt_glwe_ciphertext(
        &glwe_secret_key,
        &mut glwe,
        &plaintext_list,
        glwe_noise_distribution,
        &mut encryption_generator,
    );

    let clear: Vec<u64> = (0u64..(glwe.polynomial_size() as u64 * glwe.polynomial_size() as u64))
        .collect()
        .iter()
        .map(|x| x % (glwe.polynomial_size() as u64))
        .collect();


    let mut out =
        GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);

    let gpu_index = 0;
    let streams = CudaStreams::new_single_gpu(GpuIndex(gpu_index));

    let clear_gpu = CudaVec::from_cpu_async(clear, &streams, 0);

    let mut d_output_glwe = CudaGlweCiphertextList::from_glwe_ciphertext(&glwe, &streams);

    let mut d_output_glwe = CudaGlweCiphertextList::new(
        glwe_secret_key.glwe_dimension(),
        glwe_secret_key.polynomial_size(),
        GlweCiphertextCount(1),
        ciphertext_modulus,
        &streams,
    );

    for (mut out_poly, in_poly) in d_output_glwe.0.d_vec
        .as_mut_polynomial_list()
        .iter_mut()
        .zip(glwe.as_polynomial_list().iter())
    {
        cuda_wrapping_polynomial_mul_one_to_many(
            &mut out_poly,
            &in_poly,
            &clear_gpu,
            &streams,
        );
    }

    decrypt_glwe();
}

create_gpu_parameterized_test!(glwe_dot_product_with_clear);
