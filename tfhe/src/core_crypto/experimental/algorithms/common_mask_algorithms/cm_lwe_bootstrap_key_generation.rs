//! Module containing primitives pertaining to the generation of
//! [`standard CommonMask LWE bootstrap keys`](`CmLweBootstrapKey`).

use crate::core_crypto::commons::generators::EncryptionRandomGenerator;
use crate::core_crypto::commons::math::random::{Distribution, Uniform};
use crate::core_crypto::experimental::prelude::*;
use crate::core_crypto::prelude::*;
use itertools::Itertools;
use rayon::prelude::*;

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
    for input_lwe_secret_key in input_lwe_secret_keys {
        assert!(
            output.input_lwe_dimension() == input_lwe_secret_key.lwe_dimension(),
            "Mismatched LweDimension between input LWE secret key and LWE bootstrap key. \
            Input LWE secret key LweDimension: {:?}, LWE bootstrap key input LweDimension {:?}.",
            input_lwe_secret_key.lwe_dimension(),
            output.input_lwe_dimension()
        );
    }
    let key_len = input_lwe_secret_keys[0].as_view().into_container().len();

    for output_glwe_secret_key in output_glwe_secret_keys {
        assert!(
            output.glwe_dimension() == output_glwe_secret_key.glwe_dimension(),
            "Mismatched GlweSize between output GLWE secret key and LWE bootstrap key. \
        Output GLWE secret key GlweSize: {:?}, LWE bootstrap key GlweSize {:?}.",
            output_glwe_secret_key.glwe_dimension(),
            output.glwe_dimension()
        );

        assert!(
            output.polynomial_size() == output_glwe_secret_key.polynomial_size(),
            "Mismatched PolynomialSize between output GLWE secret key and LWE bootstrap key. \
        Output GLWE secret key PolynomialSize: {:?}, LWE bootstrap key PolynomialSize {:?}.",
            output_glwe_secret_key.polynomial_size(),
            output.polynomial_size()
        );
    }

    let gen_iter = generator
        .par_try_fork_from_config(output.encryption_fork_config(Uniform, noise_distribution))
        .unwrap();

    // TODO: avoid secret key copies in memory
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

#[derive(Clone, Debug, PartialEq)]
pub struct CmBootstrapKeys<Scalar: UnsignedInteger> {
    pub small_lwe_sk: Vec<LweSecretKey<Vec<Scalar>>>,
    pub big_lwe_sk: Vec<LweSecretKey<Vec<Scalar>>>,
    pub bsk: CmLweBootstrapKeyOwned<Scalar>,
    pub fbsk: FourierCmLweBootstrapKeyOwned,
}
