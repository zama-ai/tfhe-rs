//! Module containing primitives pertaining to the generation of
//! [`standard LWE bootstrap keys`](`LweBootstrapKey`) and [`seeded standard LWE bootstrap
//! keys`](`SeededLweBootstrapKey`).

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::random::{Distribution, Uniform};
use crate::core_crypto::commons::noise_formulas::secure_noise::minimal_glwe_variance_for_132_bits_security_gaussian;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::experimental::fft64::common_mask::cm_bootstrap::{
    FourierCmLweBootstrapKey, FourierCmLweBootstrapKeyOwned,
};
use crate::core_crypto::experimental::prelude::*;
use crate::core_crypto::prelude::*;
use itertools::Itertools;
use rayon::prelude::*;
use serde::de::DeserializeOwned;
use serde::Serialize;

pub fn generate_cm_lwe_bootstrap_key<
    Scalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    OutputCont,
    Gen,
>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    output: &mut LweBootstrapKey<OutputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
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
        .try_fork_from_config(output.encryption_fork_config(Uniform, noise_distribution))
        .unwrap();

    for ((mut ggsw, &input_key_element), mut generator) in output
        .iter_mut()
        .zip(input_lwe_secret_key.as_ref())
        .zip(gen_iter)
    {
        encrypt_constant_ggsw_ciphertext(
            output_glwe_secret_key,
            &mut ggsw,
            Cleartext(input_key_element),
            noise_distribution,
            &mut generator,
        );
    }
}

pub fn allocate_and_generate_new_cm_lwe_bootstrap_key<
    Scalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    Gen,
>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_distribution: NoiseDistribution,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> LweBootstrapKeyOwned<Scalar>
where
    Scalar: Encryptable<Uniform, NoiseDistribution>,
    NoiseDistribution: Distribution,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    let mut bsk = LweBootstrapKeyOwned::new(
        Scalar::ZERO,
        output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        output_glwe_secret_key.polynomial_size(),
        decomp_base_log,
        decomp_level_count,
        input_lwe_secret_key.lwe_dimension(),
        ciphertext_modulus,
    );

    generate_cm_lwe_bootstrap_key(
        input_lwe_secret_key,
        output_glwe_secret_key,
        &mut bsk,
        noise_distribution,
        generator,
    );

    bsk
}

pub fn par_generate_cm_lwe_bootstrap_key<
    Scalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    OutputCont,
    Gen,
>(
    input_lwe_secret_keys: &[LweSecretKey<InputKeyCont>],
    output_glwe_secret_keys: &[GlweSecretKey<OutputKeyCont>],
    output: &mut CmLweBootstrapKey<OutputCont>,
    noise_distribution: NoiseDistribution,
    generator: &mut EncryptionRandomGenerator<Gen>,
) where
    Scalar: Encryptable<Uniform, NoiseDistribution> + Sync + Send,
    NoiseDistribution: Distribution + Sync,
    InputKeyCont: Container<Element = Scalar> + std::fmt::Debug,
    OutputKeyCont: Container<Element = Scalar> + Sync,
    OutputCont: ContainerMut<Element = Scalar>,
    Gen: ParallelByteRandomGenerator,
{
    assert!(
        output.input_lwe_dimension() == input_lwe_secret_keys[0].lwe_dimension(),
        "Mismatched LweDimension between input LWE secret key and LWE bootstrap key. \
        Input LWE secret key LweDimension: {:?}, LWE bootstrap key input LweDimension {:?}.",
        input_lwe_secret_keys[0].lwe_dimension(),
        output.input_lwe_dimension()
    );

    assert!(
        output.glwe_dimension() == output_glwe_secret_keys[0].glwe_dimension(),
        "Mismatched GlweSize between output GLWE secret key and LWE bootstrap key. \
        Output GLWE secret key GlweSize: {:?}, LWE bootstrap key GlweSize {:?}.",
        output_glwe_secret_keys[0].glwe_dimension(),
        output.glwe_dimension()
    );

    assert!(
        output.polynomial_size() == output_glwe_secret_keys[0].polynomial_size(),
        "Mismatched PolynomialSize between output GLWE secret key and LWE bootstrap key. \
        Output GLWE secret key PolynomialSize: {:?}, LWE bootstrap key PolynomialSize {:?}.",
        output_glwe_secret_keys[0].polynomial_size(),
        output.polynomial_size()
    );

    let gen_iter = generator
        .par_try_fork_from_config(output.encryption_fork_config(Uniform, noise_distribution))
        .unwrap();

    let key_len = input_lwe_secret_keys[0].as_view().into_container().len();

    let transposed_keys = (0..key_len)
        .map(|i| {
            input_lwe_secret_keys
                .iter()
                .map(|key| Cleartext(key.as_view().into_container()[i]))
                .collect_vec()
        })
        .collect_vec();

    output
        .par_iter_mut()
        .zip(transposed_keys.par_iter())
        .zip(gen_iter)
        .for_each(|((mut ggsw, input_key_element), mut generator)| {
            par_encrypt_constant_cm_ggsw_ciphertext(
                output_glwe_secret_keys,
                &mut ggsw,
                input_key_element,
                noise_distribution,
                &mut generator,
            );
        });
}

pub fn par_allocate_and_generate_new_cm_lwe_bootstrap_key<
    Scalar,
    NoiseDistribution,
    InputKeyCont,
    OutputKeyCont,
    Gen,
>(
    input_lwe_secret_key: &LweSecretKey<InputKeyCont>,
    output_glwe_secret_key: &GlweSecretKey<OutputKeyCont>,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    noise_distribution: NoiseDistribution,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    generator: &mut EncryptionRandomGenerator<Gen>,
) -> LweBootstrapKeyOwned<Scalar>
where
    Scalar: Encryptable<Uniform, NoiseDistribution> + Sync + Send,
    NoiseDistribution: Distribution + Sync,
    InputKeyCont: Container<Element = Scalar>,
    OutputKeyCont: Container<Element = Scalar> + Sync,
    Gen: ParallelByteRandomGenerator,
{
    let mut bsk = LweBootstrapKeyOwned::new(
        Scalar::ZERO,
        output_glwe_secret_key.glwe_dimension().to_glwe_size(),
        output_glwe_secret_key.polynomial_size(),
        decomp_base_log,
        decomp_level_count,
        input_lwe_secret_key.lwe_dimension(),
        ciphertext_modulus,
    );

    par_generate_lwe_bootstrap_key(
        input_lwe_secret_key,
        output_glwe_secret_key,
        &mut bsk,
        noise_distribution,
        generator,
    );

    bsk
}

#[derive(Clone, Debug, PartialEq)]
pub struct CmBootstrapKeys<Scalar: UnsignedInteger> {
    pub small_lwe_sk: Vec<LweSecretKey<Vec<Scalar>>>,
    pub big_lwe_sk: Vec<LweSecretKey<Vec<Scalar>>>,
    pub bsk: CmLweBootstrapKeyOwned<Scalar>,
    pub fbsk: FourierCmLweBootstrapKeyOwned,
}

pub fn generate_cm_pbs_keys<
    Scalar: UnsignedTorus + Sync + Send + CastFrom<usize> + CastInto<usize> + Serialize + DeserializeOwned,
>(
    params: &CmApParams,
    encryption_random_generator: &mut EncryptionRandomGenerator<DefaultRandomGenerator>,
    secret_random_generator: &mut SecretRandomGenerator<DefaultRandomGenerator>,
) -> CmBootstrapKeys<Scalar> {
    let ciphertext_modulus = CiphertextModulus::<Scalar>::new_native();

    let cm_dimension = params.cm_dimension;

    let glwe_noise_distribution =
        DynamicDistribution::new_gaussian(minimal_glwe_variance_for_132_bits_security_gaussian(
            params.glwe_dimension,
            params.polynomial_size,
            2_f64.powi(64),
        ));

    // Create the LweSecretKey
    let input_lwe_secret_keys = (0..cm_dimension.0)
        .map(|_| {
            allocate_and_generate_new_binary_lwe_secret_key(
                params.lwe_dimension,
                &mut *secret_random_generator,
            )
        })
        .collect_vec();
    let output_glwe_secret_keys = (0..cm_dimension.0)
        .map(|_| {
            allocate_and_generate_new_binary_glwe_secret_key(
                params.glwe_dimension,
                params.polynomial_size,
                &mut *secret_random_generator,
            )
        })
        .collect_vec();

    let output_lwe_secret_keys = output_glwe_secret_keys
        .iter()
        .map(|a| a.clone().into_lwe_secret_key())
        .collect_vec();

    let mut bsk = CmLweBootstrapKey::new(
        Scalar::ZERO,
        params.glwe_dimension,
        cm_dimension,
        params.polynomial_size,
        params.base_log_bs,
        params.level_bs,
        params.lwe_dimension,
        ciphertext_modulus,
    );

    par_generate_cm_lwe_bootstrap_key(
        &input_lwe_secret_keys,
        &output_glwe_secret_keys,
        &mut bsk,
        glwe_noise_distribution,
        &mut *encryption_random_generator,
    );

    let mut fbsk = FourierCmLweBootstrapKey::new(
        params.lwe_dimension,
        params.glwe_dimension,
        cm_dimension,
        params.polynomial_size,
        params.base_log_bs,
        params.level_bs,
    );

    par_convert_standard_cm_lwe_bootstrap_key_to_fourier(&bsk, &mut fbsk);

    CmBootstrapKeys {
        small_lwe_sk: input_lwe_secret_keys,
        big_lwe_sk: output_lwe_secret_keys,
        bsk,
        fbsk,
    }
}
