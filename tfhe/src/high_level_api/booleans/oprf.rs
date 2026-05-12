use super::{FheBool, InnerBoolean};
use crate::high_level_api::global_state;
use crate::high_level_api::keys::InternalServerKey;
use crate::high_level_api::re_randomization::{
    ReRandomizationMetadata, ReRandomizationMode, ReRandomize,
};
use crate::integer::ciphertext::{
    RadixRandomBitsRLE, ReRandomizationHashAlgo, ReRandomizationSeed,
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
    /// let ct_res = FheBool::generate_oblivious_pseudo_random(Seed(0));
    ///
    /// let dec_result: bool = ct_res.decrypt(&client_key);
    /// ```
    pub fn generate_oblivious_pseudo_random(seed: impl OprfSeed) -> Self {
        let (ciphertext, tag) = global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let sk = &key.pbs_key().key;

                let ct = key
                    .oprf_key()
                    .key
                    .generate_oblivious_pseudo_random(seed, 1, sk);
                (
                    InnerBoolean::Cpu(BooleanBlock::new_unchecked(ct)),
                    key.tag.clone(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => {
                let streams = &cuda_key.streams;
                let d_ct: CudaUnsignedRadixCiphertext = cuda_key
                    .oprf_key()
                    .generate_oblivious_pseudo_random(seed, 1, cuda_key.pbs_key(), streams);
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

    pub fn generate_oblivious_pseudo_random_and_re_randomize<
        'a,
        RRD: Into<ReRandomizationMode<'a>>,
    >(
        prf_seed: impl OprfSeed,
        re_randomization_mode: RRD,
        re_randomization_hash_algo: ReRandomizationHashAlgo,
    ) -> crate::Result<Self> {
        let prf_seed = prf_seed.into_bytes();
        let prf_seed = prf_seed.as_ref();

        let mut random_ct = Self::generate_oblivious_pseudo_random(prf_seed);

        let output_bit_sizes = RadixRandomBitsRLE::new_boolean();

        let rerand_seed = ReRandomizationSeed::new_prf_rerand_seed(
            re_randomization_hash_algo,
            prf_seed,
            core::slice::from_ref(&output_bit_sizes),
        );

        random_ct.re_randomize(re_randomization_mode, rerand_seed)?;

        Ok(random_ct)
    }
}

#[cfg(test)]
#[cfg(feature = "gpu")]
mod test {
    use crate::prelude::FheDecrypt;

    #[test]
    fn test_oprf_boolean() {
        let config = crate::ConfigBuilder::default()
            .use_dedicated_oprf_key(true)
            .build();
        let client_key = crate::ClientKey::generate(config);
        let compressed_server_key = crate::CompressedServerKey::new(&client_key);
        let gpu_key = compressed_server_key.decompress_to_gpu();
        crate::set_server_key(gpu_key);

        let rnd = crate::FheBool::generate_oblivious_pseudo_random(crate::Seed(123));
        let decrypted_result: bool = rnd.decrypt(&client_key);
        println!("Random bool: {decrypted_result}");
    }
}
