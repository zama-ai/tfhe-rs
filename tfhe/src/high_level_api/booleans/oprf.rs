use super::{FheBool, InnerBoolean};
use crate::high_level_api::global_state;
use crate::high_level_api::keys::InternalServerKey;
use crate::high_level_api::re_randomization::{
    ReRandomizationHashAlgo, ReRandomizationMetadata, ReRandomizationMode,
};
#[cfg(feature = "gpu")]
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
#[cfg(feature = "gpu")]
use crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
use crate::integer::BooleanBlock;
use crate::shortint::OprfSeed;

impl FheBool {
    /// Generates an encrypted boolean
    /// taken uniformly using the given seed.
    /// The encrypted value is oblivious to the server.
    /// It can be useful to make server random generation deterministic.
    ///
    /// ```rust
    /// use tfhe::prelude::FheDecrypt;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheBool, Seed};
    ///
    /// let config = ConfigBuilder::default().build();
    /// let (client_key, server_key) = generate_keys(config);
    ///
    /// set_server_key(server_key);
    ///
    /// // DANGER: Using a deterministic seed is insecure and only done here to show API usage.
    /// // The proper way of generating a seed depends on your application.
    /// let ct_res = FheBool::generate_oblivious_pseudo_random(Seed(0));
    ///
    /// let dec_result: bool = ct_res.decrypt(&client_key);
    /// ```
    pub fn generate_oblivious_pseudo_random(seed: impl OprfSeed) -> Self {
        let (ciphertext, tag) = global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let sk = &key.pbs_key().key;

                let ct_wrapped = key
                    .oprf_key()
                    .key
                    .generate_oblivious_pseudo_random_bits_chunks(seed, &[1], sk);

                // We have to do the double unwrap, we want to keep as little primitives as possible
                // for PRF since they also need a rerandomized_variant, so we don't have a single
                // block primitive for that
                let ct = ct_wrapped
                    .into_iter()
                    .next()
                    .expect("A single chunk was expected, got 0")
                    .into_iter()
                    .next()
                    .expect("A single ciphertext was expected, got 0");

                (
                    InnerBoolean::Cpu(BooleanBlock::new_unchecked(ct)),
                    key.tag.clone(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                // 1 block with 1 bit of data is a boolean
                let d_ct: CudaUnsignedRadixCiphertext = cuda_key
                    .oprf_key()
                    .par_generate_oblivious_pseudo_random_unsigned_integer_bounded(
                        seed,
                        1,
                        1,
                        cuda_key.pbs_key(),
                        streams,
                    );
                (
                    InnerBoolean::Cuda(CudaBooleanBlock::from_cuda_radix_ciphertext(
                        d_ct.ciphertext,
                    )),
                    cuda_key.tag.clone(),
                )
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support random bool generation")
            }
        });
        Self::new(ciphertext, tag, ReRandomizationMetadata::default())
    }

    /// Generates an encrypted boolean taken uniformly using the given seed.
    /// The encrypted value is oblivious to the server.
    /// It can be useful to make server random generation deterministic.
    ///
    /// This variant also applies a re-randomization to the output of hte PRF.
    /// Depending on your application you may need to use this variant of the API.
    ///
    /// ```rust
    /// use tfhe::prelude::*;
    /// use tfhe::shortint::parameters::*;
    /// use tfhe::{
    ///     generate_keys, set_server_key, ConfigBuilder, FheBool, ReRandomizationHashAlgo,
    ///     ReRandomizationMode,
    /// };
    ///
    /// let params = PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    /// let re_rand_params = ReRandomizationParameters::DerivedCPKWithoutKeySwitch;
    ///
    /// let config = ConfigBuilder::with_custom_parameters(params)
    ///     .enable_ciphertext_re_randomization(re_rand_params)
    ///     .build();
    ///
    /// let (client_key, server_key) = generate_keys(config);
    ///
    /// set_server_key(server_key);
    ///
    /// let seed = [0u8; 32].as_slice();
    ///
    /// let ct_res = FheBool::generate_oblivious_pseudo_random(seed);
    ///
    /// // DANGER: Using a deterministic seed is insecure and only done here to show API usage.
    /// // The proper way of generating a seed depends on your application.
    /// let ct_res_rerand = FheBool::generate_oblivious_pseudo_random_and_re_randomize(
    ///     seed,
    ///     ReRandomizationMode::default(),
    ///     // Safe standardized choice
    ///     ReRandomizationHashAlgo::Shake256,
    /// )
    /// .unwrap();
    ///
    /// let dec_result: bool = ct_res.decrypt(&client_key);
    /// let dec_result_rerand: bool = ct_res_rerand.decrypt(&client_key);
    ///
    /// // Re-randomization does not change the contained value
    /// // just the values representing the ciphertext
    /// assert_eq!(dec_result, dec_result_rerand);
    /// ```
    pub fn generate_oblivious_pseudo_random_and_re_randomize<
        'a,
        RRD: Into<ReRandomizationMode<'a>>,
    >(
        seed: impl OprfSeed,
        re_randomization_mode: RRD,
        re_randomization_hash_algo: ReRandomizationHashAlgo,
    ) -> crate::Result<Self> {
        let re_randomization_mode: ReRandomizationMode = re_randomization_mode.into();
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let sk = key.pbs_key();
                let rerand_key =
                    key.integer_re_randomization_key_from_mode(re_randomization_mode)?;

                // 1 block with 1 bit of data is a boolean
                let ct_wrapped = key
                    .oprf_key()
                    .par_generate_oblivious_pseudo_random_unsigned_integer_bounded_and_re_randomize(
                        seed,
                        1,
                        1,
                        sk,
                        &rerand_key,
                        re_randomization_hash_algo,
                    )?;

                let ct = ct_wrapped.blocks.into_iter().next().unwrap();

                Ok((
                    InnerBoolean::Cpu(BooleanBlock::new_unchecked(ct)),
                    key.tag.clone(),
                ))
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let rerand_key =
                    cuda_key.integer_re_randomization_key_from_mode(re_randomization_mode)?;

                // 1 block with 1 bit of data is a boolean
                let d_ct: CudaUnsignedRadixCiphertext = cuda_key
                    .oprf_key()
                    .par_generate_oblivious_pseudo_random_unsigned_integer_bounded_and_re_randomize(
                        seed,
                        1,
                        1,
                        cuda_key.pbs_key(),
                        &rerand_key,
                        re_randomization_hash_algo,
                        streams,
                    )?;
                Ok((
                    InnerBoolean::Cuda(CudaBooleanBlock::from_cuda_radix_ciphertext(
                        d_ct.ciphertext,
                    )),
                    cuda_key.tag.clone(),
                ))
            }
            #[cfg(feature = "hpu")]
            InternalServerKey::Hpu(_device) => {
                panic!("Hpu does not support random bool generation")
            }
        })
        .map(|(ciphertext, tag)| Self::new(ciphertext, tag, ReRandomizationMetadata::default()))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::prelude::FheDecrypt;
    use crate::shortint::parameters::ReRandomizationParameters;

    #[test]
    fn test_oprf_boolean() {
        let config = crate::ConfigBuilder::default()
            .use_dedicated_oprf_key(true)
            .enable_ciphertext_re_randomization(
                ReRandomizationParameters::DerivedCPKWithoutKeySwitch,
            )
            .build();

        let rerand_mode = ReRandomizationMode::UseAvailableMode;

        let client_key = crate::ClientKey::generate(config);
        let cpu_key = crate::ServerKey::new(&client_key);
        crate::set_server_key(cpu_key);

        // Make sure seed generation is secure in production, this is a test setup
        let seed = crate::Seed(rand::random());

        let rnd = FheBool::generate_oblivious_pseudo_random(seed);
        let decrypted_result: bool = rnd.decrypt(&client_key);

        for hash_algo in [
            ReRandomizationHashAlgo::Blake3,
            ReRandomizationHashAlgo::Shake256,
        ] {
            let rnd_rerand = FheBool::generate_oblivious_pseudo_random_and_re_randomize(
                seed,
                rerand_mode,
                hash_algo,
            )
            .unwrap();

            let decrypted_result_rerand: bool = rnd_rerand.decrypt(&client_key);

            assert_eq!(decrypted_result, decrypted_result_rerand);
        }
    }

    #[cfg(feature = "gpu")]
    mod gpu {
        use super::*;
        #[test]
        fn test_oprf_boolean() {
            let config = crate::ConfigBuilder::default()
                .use_dedicated_oprf_key(true)
                .enable_ciphertext_re_randomization(
                    ReRandomizationParameters::DerivedCPKWithoutKeySwitch,
                )
                .build();

            let rerand_mode = ReRandomizationMode::UseAvailableMode;

            let client_key = crate::ClientKey::generate(config);
            let compressed_server_key = crate::CompressedServerKey::new(&client_key);

            // Make sure seed generation is secure in production, this is a test setup
            let seed = crate::Seed(rand::random());

            let cpu_result = {
                let cpu_key = compressed_server_key.decompress();
                crate::set_server_key(cpu_key);

                let rnd = FheBool::generate_oblivious_pseudo_random(seed);
                let decrypted_result: bool = rnd.decrypt(&client_key);

                decrypted_result
            };
            let gpu_result = {
                let gpu_key = compressed_server_key.decompress_to_gpu();
                crate::set_server_key(gpu_key);

                let rnd = FheBool::generate_oblivious_pseudo_random(seed);
                let decrypted_result: bool = rnd.decrypt(&client_key);

                for hash_algo in [
                    ReRandomizationHashAlgo::Blake3,
                    ReRandomizationHashAlgo::Shake256,
                ] {
                    let rnd_rerand = FheBool::generate_oblivious_pseudo_random_and_re_randomize(
                        seed,
                        rerand_mode,
                        hash_algo,
                    )
                    .unwrap();

                    let decrypted_result_rerand: bool = rnd_rerand.decrypt(&client_key);

                    assert_eq!(decrypted_result, decrypted_result_rerand);
                }

                decrypted_result
            };

            // Also check CPU and GPU agree
            assert_eq!(cpu_result, gpu_result, "CPU and GPU disagree on output");
        }
    }
}
