use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::crypto::secret::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::random::ByteRandomGenerator;
#[cfg(feature = "__commons_parallel")]
use crate::core_crypto::commons::math::random::ParallelByteRandomGenerator;
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::specification::dispersion::DispersionParameter;
#[cfg(feature = "__commons_parallel")]
use rayon::prelude::*;

pub fn generate_lwe_bootstrap_key<Scalar, InputKeyCont, OutputKeyCont, OutputCont, Gen>(
    input_lwe_secret_key: &LweSecretKeyBase<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKeyBase<OutputKeyCont>,
    output: &mut LweBootstrapKeyBase<OutputCont>,
    noise_parameters: impl DispersionParameter,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    assert!(
        output.input_lwe_dimension() == input_lwe_secret_key.lwe_dimension(),
        "Mismatched LweDimension between input LWE secret key and LWE bootstrap key. \
        Input LWE secret key LweDimension: {:?}, LWE bootstrap key input LweDimension {:?}.",
        input_lwe_secret_key.lwe_dimension(),
        output.input_lwe_dimension()
    );

    assert!(
        output.glwe_size() == output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        "Mismatched GlweSize between output GLWE secret key and LWE bootstrap key. \
        Output GLWE secret key GlweSize: {:?}, LWE bootstrap key GlweSize {:?}.",
        output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        output.glwe_size()
    );

    assert!(
        output.polynomial_size() == output_glwe_secret_key.polynomial_size(),
        "Mismatched PolynomialSize between output GLWE secret key and LWE bootstrap key. \
        Output GLWE secret key PolynomialSize: {:?}, LWE bootstrap key PolynomialSize {:?}.",
        output_glwe_secret_key.polynomial_size(),
        output.polynomial_size()
    );

    let gen_iter = generator
        .fork_bsk_to_ggsw::<Scalar>(
            output.input_lwe_dimension(),
            output.decomposition_level_count(),
            output.glwe_size(),
            output.polynomial_size(),
        )
        .unwrap();

    for ((mut ggsw, &input_key_element), mut generator) in output
        .iter_mut()
        .zip(input_lwe_secret_key.as_ref())
        .zip(gen_iter)
    {
        encrypt_ggsw_ciphertext(
            output_glwe_secret_key,
            &mut ggsw,
            Plaintext(input_key_element),
            noise_parameters,
            &mut generator,
        );
    }
}

#[cfg(feature = "__commons_parallel")]
pub fn par_generate_lwe_bootstrap_key<Scalar, InputKeyCont, OutputKeyCont, OutputCont, Gen>(
    input_lwe_secret_key: &LweSecretKeyBase<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKeyBase<OutputKeyCont>,
    output: &mut LweBootstrapKeyBase<OutputCont>,
    noise_parameters: impl DispersionParameter + Sync,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: UnsignedTorus + Sync + Send,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar> + Sync,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ParallelByteRandomGenerator,
{
    assert!(
        output.input_lwe_dimension() == input_lwe_secret_key.lwe_dimension(),
        "Mismatched LweDimension between input LWE secret key and LWE bootstrap key. \
        Input LWE secret key LweDimension: {:?}, LWE bootstrap key input LweDimension {:?}.",
        input_lwe_secret_key.lwe_dimension(),
        output.input_lwe_dimension()
    );

    assert!(
        output.glwe_size() == output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        "Mismatched GlweSize between output GLWE secret key and LWE bootstrap key. \
        Output GLWE secret key GlweSize: {:?}, LWE bootstrap key GlweSize {:?}.",
        output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        output.glwe_size()
    );

    assert!(
        output.polynomial_size() == output_glwe_secret_key.polynomial_size(),
        "Mismatched PolynomialSize between output GLWE secret key and LWE bootstrap key. \
        Output GLWE secret key PolynomialSize: {:?}, LWE bootstrap key PolynomialSize {:?}.",
        output_glwe_secret_key.polynomial_size(),
        output.polynomial_size()
    );

    let gen_iter = generator
        .par_fork_bsk_to_ggsw::<Scalar>(
            output.input_lwe_dimension(),
            output.decomposition_level_count(),
            output.glwe_size(),
            output.polynomial_size(),
        )
        .unwrap();

    output
        .par_iter_mut()
        .zip(input_lwe_secret_key.as_ref().par_iter())
        .zip(gen_iter)
        .for_each(|((mut ggsw, &input_key_element), mut generator)| {
            par_encrypt_ggsw_ciphertext(
                output_glwe_secret_key,
                &mut ggsw,
                Plaintext(input_key_element),
                noise_parameters,
                &mut generator,
            );
        })
}

#[cfg(test)]
mod test {
    use crate::core_crypto::algorithms::generate_lwe_bootstrap_key;
    use crate::core_crypto::commons::crypto::bootstrap::StandardBootstrapKey;
    use crate::core_crypto::commons::crypto::secret::generators::{
        DeterministicSeeder, EncryptionRandomGenerator,
    };
    use crate::core_crypto::commons::crypto::secret::{GlweSecretKey, LweSecretKey};
    use crate::core_crypto::commons::math::random::Seed;
    use crate::core_crypto::commons::math::tensor::*;
    use crate::core_crypto::commons::math::torus::UnsignedTorus;
    use crate::core_crypto::commons::test_tools::new_secret_random_generator;
    use crate::core_crypto::entities::{GlweSecretKeyBase, LweBootstrapKey, LweSecretKeyBase};
    use crate::core_crypto::prelude::{
        DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
        StandardDev,
    };
    use concrete_csprng::generators::SoftwareRandomGenerator;

    fn test_refactored_bsk_equivalence<T: UnsignedTorus + Send + Sync>() {
        for _ in 0..10 {
            let lwe_dim =
                LweDimension(crate::core_crypto::commons::test_tools::random_usize_between(5..10));
            let glwe_dim =
                GlweDimension(crate::core_crypto::commons::test_tools::random_usize_between(5..10));
            let poly_size = PolynomialSize(
                crate::core_crypto::commons::test_tools::random_usize_between(5..10),
            );
            let level = DecompositionLevelCount(
                crate::core_crypto::commons::test_tools::random_usize_between(2..5),
            );
            let base_log = DecompositionBaseLog(
                crate::core_crypto::commons::test_tools::random_usize_between(2..5),
            );
            let mask_seed = Seed(crate::core_crypto::commons::test_tools::any_usize() as u128);
            let deterministic_seeder_seed =
                Seed(crate::core_crypto::commons::test_tools::any_usize() as u128);

            let mut secret_generator = new_secret_random_generator();
            let lwe_sk = LweSecretKey::generate_binary(lwe_dim, &mut secret_generator);
            let glwe_sk =
                GlweSecretKey::generate_binary(glwe_dim, poly_size, &mut secret_generator);

            let mut bsk = StandardBootstrapKey::allocate(
                T::ZERO,
                glwe_dim.to_glwe_size(),
                poly_size,
                level,
                base_log,
                lwe_dim,
            );

            let mut encryption_generator =
                EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(
                    mask_seed,
                    &mut DeterministicSeeder::<SoftwareRandomGenerator>::new(
                        deterministic_seeder_seed,
                    ),
                );

            bsk.fill_with_new_key(
                &lwe_sk,
                &glwe_sk,
                StandardDev::from_standard_dev(10.),
                &mut encryption_generator,
            );

            let mut refactored_bsk = LweBootstrapKey::new(
                T::ZERO,
                glwe_dim.to_glwe_size(),
                poly_size,
                base_log,
                level,
                lwe_dim,
            );

            let mut encryption_generator =
                EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(
                    mask_seed,
                    &mut DeterministicSeeder::<SoftwareRandomGenerator>::new(
                        deterministic_seeder_seed,
                    ),
                );

            generate_lwe_bootstrap_key(
                &LweSecretKeyBase::from_container(lwe_sk.as_tensor().as_slice()),
                &GlweSecretKeyBase::from_container(glwe_sk.as_tensor().as_slice(), poly_size),
                &mut refactored_bsk,
                StandardDev::from_standard_dev(10.),
                &mut encryption_generator,
            );

            assert_eq!(bsk.as_tensor().as_slice(), refactored_bsk.as_ref());
        }
    }

    #[test]
    fn test_refactored_bsk_u32() {
        test_refactored_bsk_equivalence::<u32>()
    }

    #[test]
    fn test_refactored_bsk_u64() {
        test_refactored_bsk_equivalence::<u64>()
    }
}

#[cfg(feature = "__commons_parallel")]
#[cfg(test)]
mod parallel_test {
    use crate::core_crypto::algorithms::{
        allocate_and_generate_new_binary_glwe_secret_key,
        allocate_and_generate_new_binary_lwe_secret_key, generate_lwe_bootstrap_key,
        par_generate_lwe_bootstrap_key,
    };
    use crate::core_crypto::commons::crypto::secret::generators::{
        DeterministicSeeder, EncryptionRandomGenerator,
    };
    use crate::core_crypto::commons::math::random::Seed;
    use crate::core_crypto::commons::math::torus::UnsignedTorus;
    use crate::core_crypto::commons::test_tools::new_secret_random_generator;
    use crate::core_crypto::entities::LweBootstrapKey;
    use crate::core_crypto::prelude::{
        DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
        StandardDev,
    };
    use concrete_csprng::generators::SoftwareRandomGenerator;

    fn test_refactored_bsk_parallel_gen_equivalence<T: UnsignedTorus + Send + Sync>() {
        for _ in 0..10 {
            let lwe_dim =
                LweDimension(crate::core_crypto::commons::test_tools::random_usize_between(5..10));
            let glwe_dim =
                GlweDimension(crate::core_crypto::commons::test_tools::random_usize_between(5..10));
            let poly_size = PolynomialSize(
                crate::core_crypto::commons::test_tools::random_usize_between(5..10),
            );
            let level = DecompositionLevelCount(
                crate::core_crypto::commons::test_tools::random_usize_between(2..5),
            );
            let base_log = DecompositionBaseLog(
                crate::core_crypto::commons::test_tools::random_usize_between(2..5),
            );
            let mask_seed = Seed(crate::core_crypto::commons::test_tools::any_usize() as u128);
            let deterministic_seeder_seed =
                Seed(crate::core_crypto::commons::test_tools::any_usize() as u128);

            let mut secret_generator = new_secret_random_generator();
            let lwe_sk =
                allocate_and_generate_new_binary_lwe_secret_key(lwe_dim, &mut secret_generator);
            let glwe_sk = allocate_and_generate_new_binary_glwe_secret_key(
                glwe_dim,
                poly_size,
                &mut secret_generator,
            );

            let mut parallel_bsk = LweBootstrapKey::new(
                T::ZERO,
                glwe_dim.to_glwe_size(),
                poly_size,
                base_log,
                level,
                lwe_dim,
            );

            let mut encryption_generator =
                EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(
                    mask_seed,
                    &mut DeterministicSeeder::<SoftwareRandomGenerator>::new(
                        deterministic_seeder_seed,
                    ),
                );

            par_generate_lwe_bootstrap_key(
                &lwe_sk,
                &glwe_sk,
                &mut parallel_bsk,
                StandardDev::from_standard_dev(10.),
                &mut encryption_generator,
            );

            let mut sequential_bsk = LweBootstrapKey::new(
                T::ZERO,
                glwe_dim.to_glwe_size(),
                poly_size,
                base_log,
                level,
                lwe_dim,
            );

            let mut encryption_generator =
                EncryptionRandomGenerator::<SoftwareRandomGenerator>::new(
                    mask_seed,
                    &mut DeterministicSeeder::<SoftwareRandomGenerator>::new(
                        deterministic_seeder_seed,
                    ),
                );

            generate_lwe_bootstrap_key(
                &lwe_sk,
                &glwe_sk,
                &mut sequential_bsk,
                StandardDev::from_standard_dev(10.),
                &mut encryption_generator,
            );

            assert_eq!(parallel_bsk.as_ref(), sequential_bsk.as_ref());
        }
    }

    #[test]
    fn test_refactored_bsk_parallel_gen_equivalence_u32() {
        test_refactored_bsk_parallel_gen_equivalence::<u32>()
    }

    #[test]
    fn test_refactored_bsk_parallel_gen_equivalence_u64() {
        test_refactored_bsk_parallel_gen_equivalence::<u64>()
    }
}
