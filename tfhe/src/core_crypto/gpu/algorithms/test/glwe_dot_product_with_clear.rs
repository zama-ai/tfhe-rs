use super::*;

use crate::core_crypto::gpu::vec::{CudaVec, GpuIndex};
use crate::core_crypto::gpu::CudaStreams;

use crate::core_crypto::gpu::algorithms::glwe_linear_algebra::*;
use crate::core_crypto::gpu::glwe_ciphertext_list::CudaGlweCiphertextList;
use crate::core_crypto::prelude::polynomial_algorithms::polynomial_wrapping_mul;
use crate::core_crypto::prelude::ContiguousEntityContainerMut;

use rand::distributions::Uniform;
use rand::Rng;

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

pub fn encode_data_for_encryption<Scalar, OutputCont>(
    input: &[Scalar],
    plaintext_list: &mut PlaintextList<OutputCont>,
    bits_reserved_for_computation: usize,
    ciphertext_modulus: CiphertextModulus<Scalar>,
) where
    Scalar: UnsignedInteger,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert!(input.len() <= plaintext_list.entity_count());

    let delta = encryption_delta(bits_reserved_for_computation, ciphertext_modulus);

    for (plain, input) in plaintext_list.iter_mut().zip(input.iter()) {
        *plain.0 = (*input) * delta;
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
    decrypt_glwe_ciphertext(glwe_secret_key, glwe, &mut decrypted);

    let mut decoded = vec![Scalar::ZERO; decrypted.plaintext_count().0];
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

pub fn decrypt_lwe<Scalar, InputCont, KeyCont>(
    lwe_secret_key: &LweSecretKey<KeyCont>,
    lwe: &LweCiphertext<InputCont>,
    bits_reserved_for_computation: usize,
) -> Scalar
where
    Scalar: UnsignedTorus,
    InputCont: Container<Element = Scalar>,
    KeyCont: Container<Element = Scalar>,
{
    let decrypted_value = decrypt_lwe_ciphertext(lwe_secret_key, lwe);

    let ciphertext_modulus = lwe.ciphertext_modulus();
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

    let mut decoded_value =
        (decomposer.closest_representable(decrypted_value.0) / delta) % decryption_modulus;

    if decoded_value >= decryption_modulus / Scalar::TWO {
        decoded_value = (decryption_modulus - decoded_value).wrapping_neg();
    }

    decoded_value
}
/// Test that a GLWE can be multiplied with a list of clear polynomials.
/// This test does not add encryption noise to ensure deterministic
/// results. The polynomials are stored in a single CudaVec on device.
fn glwe_dot_product_with_clear<Scalar: UnsignedTorus + CastFrom<usize>>(
    _params: ClassicTestParams<Scalar>,
) {
    let mut rng = rand::rng();

    let poly_size = 2 << rng.gen_range(8usize..12);
    let n_polys_rhs = if rng.gen_range(0..2) == 0 {
        poly_size
    } else {
        rng.gen_range(0..poly_size * 2)
    };

    let encryption_glwe_dimension = GlweDimension(1);
    let glwe_size = encryption_glwe_dimension.to_glwe_size();
    let polynomial_size = PolynomialSize(poly_size as usize);
    let ciphertext_modulus = CiphertextModulus::new_native();
    let glwe_noise_distribution = Gaussian::from_dispersion_parameter(StandardDev(0.0), 0.0);

    let bits_reserved_for_computation = 27;

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

    // Generate list of polynomials
    let clear_range: Vec<usize> = (0usize..(poly_size * n_polys_rhs)).collect();
    let clear_polys: Vec<Scalar> = clear_range
        .iter()
        .map(|x| Scalar::cast_from(poly_size - 1 - x % poly_size))
        .collect();

    // Generate GLWE and list of polynomials
    let mut glwe =
        GlweCiphertext::new(Scalar::ZERO, glwe_size, polynomial_size, ciphertext_modulus);

    let range = Uniform::new(0, 32);
    let to_encrypt: Vec<usize> = (0usize..poly_size).map(|_| rng.sample(range)).collect();

    let to_encrypt_vec: Vec<Scalar> = to_encrypt.iter().map(|&x| Scalar::cast_from(x)).collect();
    let clear_poly_rhs = Polynomial::from_container(clear_polys[0..poly_size].to_vec());

    // Encrypt GLWE
    let mut plaintext_list = PlaintextList::new(
        Scalar::ZERO,
        PlaintextCount(glwe_secret_key.polynomial_size().0),
    );

    encode_data_for_encryption(
        to_encrypt_vec.as_slice(),
        &mut plaintext_list,
        bits_reserved_for_computation,
        ciphertext_modulus,
    );

    encrypt_glwe_ciphertext(
        &glwe_secret_key,
        &mut glwe,
        &plaintext_list,
        glwe_noise_distribution,
        &mut encryption_generator,
    );

    // CPU polynomial product
    // only a single GLWE vs poly product is computed as all the clear polys
    // are the same
    let mut out_cpu = GlweCiphertext::new(
        Scalar::ZERO,
        glwe.glwe_size(),
        glwe.polynomial_size(),
        glwe.ciphertext_modulus(),
    );

    for (mut out_poly, in_poly) in out_cpu
        .as_mut_polynomial_list()
        .iter_mut()
        .zip(glwe.as_polynomial_list().iter())
    {
        polynomial_wrapping_mul(&mut out_poly, &in_poly, &clear_poly_rhs);
    }

    // GPU polynomial product
    let gpu_index = 0;
    let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));

    let d_input_glwe = CudaGlweCiphertextList::from_glwe_ciphertext(&glwe, &streams);

    let mut d_output_lwe = CudaLweCiphertextList::<Scalar>::new(
        LweDimension(poly_size),
        LweCiphertextCount(n_polys_rhs),
        ciphertext_modulus,
        &streams,
    );

    assert_eq!(d_output_lwe.0.d_vec.len(), n_polys_rhs * (poly_size + 1));

    unsafe {
        let clear_gpu = CudaVec::from_cpu_async(clear_polys.as_ref(), &streams, 0);

        cuda_glwe_dot_product_with_clear_one_to_many(
            &d_input_glwe,
            &clear_gpu,
            &mut d_output_lwe,
            &streams,
        );
    }

    let output_lwe_list = d_output_lwe.to_lwe_ciphertext_list(&streams);

    let result_lwe = output_lwe_list.get(0);

    let glwe_secret_key_as_lwe_secret_key = glwe_secret_key.as_lwe_secret_key();

    // On CPU we decrypt the entire GLWE and extract the Nth degree value in the clear
    // on GPU we use GLWE sample extract to get the dot product result
    let decrypted_result_gpu = decrypt_lwe(
        &glwe_secret_key_as_lwe_secret_key,
        &result_lwe,
        bits_reserved_for_computation,
    );
    let decrypted_result_cpu =
        decrypt_glwe(&glwe_secret_key, &out_cpu, bits_reserved_for_computation);

    let dot_product_gpu = decrypted_result_gpu;
    let dot_product_cpu = decrypted_result_cpu.last().unwrap();

    assert_eq!(
        dot_product_gpu, *dot_product_cpu,
        "Error multiplying GLWE with polysize {poly_size} with {n_polys_rhs} clear polys",
    );
}

use crate::core_crypto::gpu::lwe_ciphertext_list::CudaLweCiphertextList;

/// Test direct modular polynomial multiplication on GPU.
/// This test does not encrypt anything, it just checks
/// that one lhs polynomial can be multiplied with many rhs polynomials,
/// and finally checks that all coefficients in the GPU result
/// match those in the CPU result
fn poly_product_with_clear<Scalar: UnsignedTorus + CastFrom<usize>>(
    _params: ClassicTestParams<Scalar>,
) {
    let mut rng = rand::rng();
    let poly_size = 2 << rng.gen_range(8usize..12);
    let n_polys_rhs = if rng.gen_range(0..2) == 0 {
        poly_size
    } else {
        rng.gen_range(0..poly_size * 2)
    };
    let polynomial_size = PolynomialSize(poly_size as usize);

    let range = Uniform::new(0, 32);
    let clear_range_lhs: Vec<usize> = (0usize..poly_size).map(|_| rng.sample(range)).collect();

    let clear_lhs: Vec<Scalar> = clear_range_lhs
        .iter()
        .map(|&x| Scalar::cast_from(x))
        .collect();

    let clear_range_rhs: Vec<usize> = (0usize..(poly_size * n_polys_rhs)).collect();
    let clear_rhs: Vec<Scalar> = clear_range_rhs
        .iter()
        .map(|x| Scalar::cast_from(x % poly_size))
        .collect();

    let poly_lhs = Polynomial::from_container(clear_lhs);
    let poly_list_rhs = PolynomialList::from_container(clear_rhs, polynomial_size);
    let mut result_reference_cpu = PolynomialList::new(
        Scalar::ZERO,
        polynomial_size,
        poly_list_rhs.polynomial_count(),
    );

    for (rhs, mut out) in poly_list_rhs.iter().zip(result_reference_cpu.iter_mut()) {
        polynomial_wrapping_mul(&mut out, &poly_lhs, &rhs);
    }

    let mut cpu_results = PolynomialList::new(
        Scalar::ZERO,
        polynomial_size,
        poly_list_rhs.polynomial_count(),
    );

    let gpu_index = 0;
    let streams = CudaStreams::new_single_gpu(GpuIndex::new(gpu_index));

    unsafe {
        let clear_gpu_lhs = CudaVec::from_cpu_async(poly_lhs.as_ref(), &streams, 0);
        let clear_gpu_rhs = CudaVec::from_cpu_async(poly_list_rhs.as_ref(), &streams, 0);
        let mut clear_result_gpu = CudaVec::new(result_reference_cpu.as_ref().len(), &streams, 0);

        cuda_wrapping_polynomial_mul_one_to_many(
            &clear_gpu_lhs, //d_input_glwe.0.d_vec,
            &clear_gpu_rhs,
            &mut clear_result_gpu,
            &streams,
        );

        clear_result_gpu.copy_to_cpu_async(cpu_results.as_mut(), &streams, 0);
        streams.synchronize();
    }

    assert_eq!(
        cpu_results.polynomial_count().0,
        result_reference_cpu.polynomial_count().0
    );

    let cnt = cpu_results
        .as_ref()
        .iter()
        .zip(result_reference_cpu.get(0).iter())
        .filter(|(x, y)| x != y)
        .count();

    assert_eq!(cnt, 0);
}

create_gpu_parameterized_test!(glwe_dot_product_with_clear);
create_gpu_parameterized_test!(poly_product_with_clear);
