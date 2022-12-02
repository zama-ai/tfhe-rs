use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::crypto::secret::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::decomposition::DecompositionLevel;
use crate::core_crypto::commons::math::random::ByteRandomGenerator;
#[cfg(feature = "__commons_parallel")]
use crate::core_crypto::commons::math::random::ParallelByteRandomGenerator;
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::specification::dispersion::DispersionParameter;
#[cfg(feature = "__commons_parallel")]
use rayon::prelude::*;

pub fn encrypt_ggsw_ciphertext<Scalar, KeyCont, OutputCont, Gen>(
    glwe_secret_key: &GlweSecretKeyBase<KeyCont>,
    output: &mut GgswCiphertextBase<OutputCont>,
    encoded: Plaintext<Scalar>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        output.polynomial_size() == glwe_secret_key.polynomial_size(),
        "Mismatch between polynomial sizes of output cipertexts and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.polynomial_size(),
        glwe_secret_key.polynomial_size()
    );

    assert!(
        output.glwe_size().to_glwe_dimension() == glwe_secret_key.glwe_dimension(),
        "Mismatch between GlweDimension of output cipertexts and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.glwe_size().to_glwe_dimension(),
        glwe_secret_key.glwe_dimension()
    );

    // Generators used to have same sequential and parallel key generation
    let gen_iter = generator
        .fork_ggsw_to_ggsw_levels::<Scalar>(
            output.decomposition_level_count(),
            output.glwe_size(),
            output.polynomial_size(),
        )
        .expect("Failed to split generator into ggsw levels");

    let output_glwe_size = output.glwe_size();
    let output_polynomial_size = output.polynomial_size();
    let decomp_base_log = output.decomposition_base_log();

    for (level_index, (mut level_matrix, mut generator)) in
        output.iter_mut().zip(gen_iter).enumerate()
    {
        let decomp_level = DecompositionLevel(level_index + 1);
        let factor = encoded
            .0
            .wrapping_neg()
            .wrapping_mul(Scalar::ONE << (Scalar::BITS - (decomp_base_log.0 * decomp_level.0)));

        // We iterate over the rows of the level matrix, the last row needs special treatment
        let gen_iter = generator
            .fork_ggsw_level_to_glwe::<Scalar>(output_glwe_size, output_polynomial_size)
            .expect("Failed to split generator into glwe");

        let last_row_index = level_matrix.glwe_size().0 - 1;
        let sk_poly_list = glwe_secret_key.as_polynomial_list();

        for ((row_index, mut row_as_glwe), mut generator) in level_matrix
            .as_mut_glwe_list()
            .iter_mut()
            .enumerate()
            .zip(gen_iter)
        {
            encrypt_ggsw_level_matrix_row(
                glwe_secret_key,
                (row_index, last_row_index),
                factor,
                &sk_poly_list,
                &mut row_as_glwe,
                noise_parameters,
                &mut generator,
            );
        }
    }
}

#[cfg(feature = "__commons_parallel")]
pub fn par_encrypt_ggsw_ciphertext<Scalar, KeyCont, OutputCont, Gen>(
    glwe_secret_key: &GlweSecretKeyBase<KeyCont>,
    output: &mut GgswCiphertextBase<OutputCont>,
    encoded: Plaintext<Scalar>,
    noise_parameters: impl DispersionParameter + Sync,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus + Sync + Send,
    KeyCont: Container<Element = Scalar> + Sync,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ParallelByteRandomGenerator,
{
    assert!(
        output.polynomial_size() == glwe_secret_key.polynomial_size(),
        "Mismatch between polynomial sizes of output cipertexts and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.polynomial_size(),
        glwe_secret_key.polynomial_size()
    );

    assert!(
        output.glwe_size().to_glwe_dimension() == glwe_secret_key.glwe_dimension(),
        "Mismatch between GlweDimension of output cipertexts and input secret key. \
        Got {:?} in output, and {:?} in secret key.",
        output.glwe_size().to_glwe_dimension(),
        glwe_secret_key.glwe_dimension()
    );

    // Generators used to have same sequential and parallel key generation
    let gen_iter = generator
        .par_fork_ggsw_to_ggsw_levels::<Scalar>(
            output.decomposition_level_count(),
            output.glwe_size(),
            output.polynomial_size(),
        )
        .expect("Failed to split generator into ggsw levels");

    let output_glwe_size = output.glwe_size();
    let output_polynomial_size = output.polynomial_size();
    let decomp_base_log = output.decomposition_base_log();

    output.par_iter_mut().zip(gen_iter).enumerate().for_each(
        |(level_index, (mut level_matrix, mut generator))| {
            let decomp_level = DecompositionLevel(level_index + 1);
            let factor = encoded
                .0
                .wrapping_neg()
                .wrapping_mul(Scalar::ONE << (Scalar::BITS - (decomp_base_log.0 * decomp_level.0)));

            // We iterate over the rows of the level matrix, the last row needs special treatment
            let gen_iter = generator
                .par_fork_ggsw_level_to_glwe::<Scalar>(output_glwe_size, output_polynomial_size)
                .expect("Failed to split generator into glwe");

            let last_row_index = level_matrix.glwe_size().0 - 1;
            let sk_poly_list = glwe_secret_key.as_polynomial_list();

            level_matrix
                .as_mut_glwe_list()
                .par_iter_mut()
                .enumerate()
                .zip(gen_iter)
                .for_each(|((row_index, mut row_as_glwe), mut generator)| {
                    encrypt_ggsw_level_matrix_row(
                        glwe_secret_key,
                        (row_index, last_row_index),
                        factor,
                        &sk_poly_list,
                        &mut row_as_glwe,
                        noise_parameters,
                        &mut generator,
                    );
                });
        },
    );
}

fn encrypt_ggsw_level_matrix_row<Scalar, KeyCont, InputCont, OutputCont, Gen>(
    glwe_secret_key: &GlweSecretKeyBase<KeyCont>,
    (row_index, last_row_index): (usize, usize),
    factor: Scalar,
    sk_poly_list: &PolynomialListBase<InputCont>,
    row_as_glwe: &mut GlweCiphertextBase<OutputCont>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    KeyCont: Container<Element = Scalar>,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    if row_index < last_row_index {
        // Not the last row
        let sk_poly = sk_poly_list.get(row_index);

        // Copy the key polynomial to the output body, to avoid allocating a temporary buffer
        let mut body = row_as_glwe.get_mut_body();
        body.as_mut().copy_from_slice(sk_poly.as_ref());

        update_slice_with_wrapping_scalar_mul(body.as_mut(), factor);

        encrypt_glwe_ciphertext_in_place(glwe_secret_key, row_as_glwe, noise_parameters, generator);
    } else {
        // The last row needs a slightly different treatment
        let mut body = row_as_glwe.get_mut_body();

        body.as_mut().fill(Scalar::ZERO);
        body.as_mut()[0] = factor.wrapping_neg();

        encrypt_glwe_ciphertext_in_place(glwe_secret_key, row_as_glwe, noise_parameters, generator);
    }
}

#[cfg(test)]
mod test {
    use crate::core_crypto::algorithms::encrypt_ggsw_ciphertext;
    use crate::core_crypto::commons::crypto::encoding::PlaintextList;
    use crate::core_crypto::commons::crypto::ggsw::StandardGgswCiphertext;
    use crate::core_crypto::commons::crypto::secret::generators::{
        DeterministicSeeder, EncryptionRandomGenerator,
    };
    use crate::core_crypto::commons::crypto::secret::GlweSecretKey;
    use crate::core_crypto::commons::math::random::Seed;
    use crate::core_crypto::commons::math::tensor::*;
    use crate::core_crypto::commons::math::torus::UnsignedTorus;
    use crate::core_crypto::commons::test_tools;
    use crate::core_crypto::entities::{GgswCiphertext, GlweSecretKeyBase, Plaintext};
    use crate::core_crypto::prelude::{
        DecompositionBaseLog, DecompositionLevelCount, LogStandardDev,
    };
    use concrete_csprng::generators::SoftwareRandomGenerator;

    fn test_refactored_ggsw<T: UnsignedTorus>() {
        // random settings
        let nb_ct = test_tools::random_ciphertext_count(10);
        let dimension = test_tools::random_glwe_dimension(5);
        let polynomial_size = test_tools::random_polynomial_size(200);
        let noise_parameters = LogStandardDev::from_log_standard_dev(-50.);
        let decomp_level = DecompositionLevelCount(3);
        let decomp_base_log = DecompositionBaseLog(7);
        let mut secret_generator = test_tools::new_secret_random_generator();

        // generates a secret key
        let sk = GlweSecretKey::generate_binary(dimension, polynomial_size, &mut secret_generator);

        // generates random plaintexts
        let plaintext_vector =
            PlaintextList::from_tensor(secret_generator.random_uniform_tensor::<T>(nb_ct.0));

        for plaintext in plaintext_vector.plaintext_iter() {
            let main_seed = test_tools::random_seed();
            let mask_seed = Seed(crate::core_crypto::commons::test_tools::any_usize() as u128);

            let mut generator = EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(
                mask_seed,
                &mut DeterministicSeeder::<SoftwareRandomGenerator>::new(main_seed),
            );

            let mut refactored_ggsw = GgswCiphertext::new(
                T::ZERO,
                dimension.to_glwe_size(),
                polynomial_size,
                decomp_base_log,
                decomp_level,
            );

            encrypt_ggsw_ciphertext(
                &GlweSecretKeyBase::from_container(sk.as_tensor().as_slice(), polynomial_size),
                &mut refactored_ggsw,
                Plaintext(plaintext.0),
                noise_parameters,
                &mut generator,
            );

            // control encryption
            let mut ggsw = StandardGgswCiphertext::allocate(
                T::ZERO,
                polynomial_size,
                dimension.to_glwe_size(),
                decomp_level,
                decomp_base_log,
            );

            // Recreate a generator with the known mask seed
            let mut generator = EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(
                mask_seed,
                &mut DeterministicSeeder::<SoftwareRandomGenerator>::new(main_seed),
            );

            sk.encrypt_constant_ggsw(&mut ggsw, plaintext, noise_parameters, &mut generator);

            assert_eq!(refactored_ggsw.as_ref(), ggsw.as_tensor().as_slice());
        }
    }

    #[test]
    fn test_refactored_ggsw_u32() {
        test_refactored_ggsw::<u32>()
    }

    #[test]
    fn test_refactored_ggsw_u64() {
        test_refactored_ggsw::<u64>()
    }
}
