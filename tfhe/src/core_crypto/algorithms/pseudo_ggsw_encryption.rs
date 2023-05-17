use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::dispersion::DispersionParameter;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::decomposition::DecompositionLevel;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

/// Encrypt a plaintext in a [`GGSW ciphertext`](`GgswCiphertext`) in the constant coefficient.
///
/// See the [`GGSW ciphertext formal definition`](`GgswCiphertext#ggsw-encryption`) for the
/// definition of the encryption algorithm.
///
/// ```
/// use tfhe::core_crypto::prelude::*;
///
/// // DISCLAIMER: these toy example parameters are not guaranteed to be secure or yield correct
/// // computations
/// // Define parameters for GgswCiphertext creation
/// let glwe_size_out = GlweSize(2);
/// let polynomial_size = PolynomialSize(4);
/// let glwe_size_in = GlweSize(3);
/// let polynomial_size_to_encrypt = PolynomialSize(4);
/// let decomp_base_log = DecompositionBaseLog(8);
/// let decomp_level_count = DecompositionLevelCount(2);
/// let glwe_modular_std_dev =
///     StandardDev(0.00000000000000000000000000000000000000029403601535432533);
/// let ciphertext_modulus = CiphertextModulus::new_native();
///
/// // Create the PRNG
/// let mut seeder = new_seeder();
/// let seeder = seeder.as_mut();
/// let mut encryption_generator =
///     EncryptionRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed(), seeder);
/// let mut secret_generator =
///     SecretRandomGenerator::<ActivatedRandomGenerator>::new(seeder.seed());
///
/// // Create the GlweSecretKey
/// let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_size_out.to_glwe_dimension(),
///     polynomial_size,
///     &mut secret_generator,
/// );
/// // Create the GlweSecretKey
/// let glwe_secret_key_to_encrypt = allocate_and_generate_new_binary_glwe_secret_key(
///     glwe_size_in.to_glwe_dimension(),
///     polynomial_size_to_encrypt,
///     &mut secret_generator,
/// );
///
/// // Create the plaintext
/// let plaintext = Plaintext(3u64);
///
/// // Create a new GgswCiphertext
/// let mut ggsw = PseudoGgswCiphertext::new(
///     0u64,
///     glwe_size_in,
///     glwe_size_out,
///     polynomial_size,
///     decomp_base_log,
///     decomp_level_count,
///     ciphertext_modulus,
/// );
///
/// encrypt_pseudo_ggsw_ciphertext(
///     &glwe_secret_key,
///     &glwe_secret_key_to_encrypt,
///     &mut ggsw,
///     glwe_modular_std_dev,
///     &mut encryption_generator,
/// );
/// println!("GGSW = {:?}", ggsw);
/// let decrypted = decrypt_constant_ggsw_ciphertext(&glwe_secret_key, &ggsw);
/// assert_eq!(decrypted, plaintext);
/// ```
pub fn encrypt_pseudo_ggsw_ciphertext<Scalar, KeyCont, OutputCont, Gen>(
    glwe_secret_key_out: &GlweSecretKey<KeyCont>,
    glwe_secret_key_in: &GlweSecretKey<KeyCont>,
    output: &mut PseudoGgswCiphertext<OutputCont>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        output.polynomial_size() == glwe_secret_key_out.polynomial_size(),
        "Mismatch between polynomial sizes of output ciphertexts and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.polynomial_size(),
        glwe_secret_key_out.polynomial_size()
    );

    // Generators used to have same sequential and parallel key generation
    let gen_iter = generator
        .fork_pseudo_ggsw_to_ggsw_levels::<Scalar>(
            output.decomposition_level_count(),
            output.glwe_size_in(),
            output.glwe_size_out(),
            output.polynomial_size(),
        )
        .expect("Failed to split generator into ggsw levels");

    let output_glwe_size_in = output.glwe_size_in();
    let ouptut_glwe_size_out = output.glwe_size_out();
    let output_polynomial_size = output.polynomial_size();
    let decomp_base_log = output.decomposition_base_log();
    let ciphertext_modulus = output.ciphertext_modulus();

    for (level_index, (mut level_matrix, mut generator)) in
        output.iter_mut().zip(gen_iter).enumerate()
    {
        let decomp_level = DecompositionLevel(level_index + 1);
        // We scale the factor down from the native torus to whatever our torus is, the
        // encryption process will scale it back up
        let encoded = Scalar::ONE;
        let factor = encoded
            .wrapping_neg()
            .wrapping_mul(Scalar::ONE << (Scalar::BITS - (decomp_base_log.0 * decomp_level.0)))
            .wrapping_div(ciphertext_modulus.get_power_of_two_scaling_to_native_torus());

        // We iterate over the rows of the level matrix, the last row needs special treatment
        let gen_iter = generator
            .fork_pseudo_ggsw_level_to_glwe::<Scalar>(
                output_glwe_size_in,
                ouptut_glwe_size_out,
                output_polynomial_size,
            )
            .expect("Failed to split generator into glwe");

        for ((row_index, mut row_as_glwe), mut generator) in level_matrix
            .as_mut_glwe_list()
            .iter_mut()
            .enumerate()
            .zip(gen_iter)
        {
            encrypt_pseudo_ggsw_level_matrix_row(
                glwe_secret_key_out,
                glwe_secret_key_in,
                row_index,
                factor,
                &mut row_as_glwe,
                noise_parameters,
                &mut generator,
            );
        }
    }
}

fn encrypt_pseudo_ggsw_level_matrix_row<Scalar, KeyCont, OutputCont, Gen>(
    glwe_secret_key: &GlweSecretKey<KeyCont>,
    glwe_secret_key_to_encrypt: &GlweSecretKey<KeyCont>,
    row_index: usize,
    factor: Scalar,
    row_as_glwe: &mut GlweCiphertext<OutputCont>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let sk_poly_list = glwe_secret_key_to_encrypt.as_polynomial_list();
    let sk_poly = sk_poly_list.get(row_index);

    // let poly_size = row_as_glwe.polynomial_size();
    // let ct_mod = row_as_glwe.ciphertext_modulus();
    // let glwe_size = row_as_glwe.glwe_size();

    // Copy the key polynomial to the output body, to avoid allocating a temporary buffer
    let mut body = row_as_glwe.get_mut_body();
    body.as_mut().copy_from_slice(sk_poly.as_ref());

    slice_wrapping_scalar_mul_assign(body.as_mut(), factor);
    //println!("[ggsw_encryption_row] KEY VALUE = {:?}", body.as_ref());

    encrypt_glwe_ciphertext_assign(glwe_secret_key, row_as_glwe, noise_parameters, generator);
    // let mut ct = GlweCiphertext::new(Scalar::ZERO, glwe_size, poly_size,
    //                                             ct_mod);
    // trivially_encrypt_glwe_ciphertext(&mut ct,
    // &PlaintextList::from_container(body.as_polynomial ().into_container()));

    //TODO: to remove for tests
    // let mut pt = PlaintextList::new(Scalar::ZERO, PlaintextCount(glwe_secret_key
    //     .polynomial_size().0 * glwe_secret_key.glwe_dimension().0));
    // decrypt_glwe_ciphertext(glwe_secret_key, &row_as_glwe, &mut pt);
    // println!("[ggsw_encryption_row] DECRYTPTED GLWE ROW = {:?}", pt);
}
