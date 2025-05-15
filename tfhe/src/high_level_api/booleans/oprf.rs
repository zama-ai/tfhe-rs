use super::{FheBool, InnerBoolean};
use crate::high_level_api::global_state;
#[cfg(feature = "gpu")]
use crate::high_level_api::global_state::with_thread_local_cuda_streams;
use crate::high_level_api::keys::InternalServerKey;
#[cfg(feature = "gpu")]
use crate::integer::gpu::ciphertext::boolean_value::CudaBooleanBlock;
#[cfg(feature = "gpu")]
use crate::integer::gpu::ciphertext::CudaUnsignedRadixCiphertext;
use crate::integer::BooleanBlock;
use tfhe_csprng::seeders::Seed;

impl FheBool {
    /// Generates an encrypted boolean
    /// taken uniformly using the given seed.
    /// The encryted value is oblivious to the server.
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
    pub fn generate_oblivious_pseudo_random(seed: Seed) -> Self {
        let (ciphertext, tag) = global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let sk = &key.pbs_key().key;

                let ct = sk.generate_oblivious_pseudo_random(seed, 1);
                (
                    InnerBoolean::Cpu(BooleanBlock::new_unchecked(ct)),
                    key.tag.clone(),
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(cuda_key) => with_thread_local_cuda_streams(|streams| {
                let d_ct: CudaUnsignedRadixCiphertext = cuda_key
                    .key
                    .key
                    .generate_oblivious_pseudo_random(seed, 1, streams);
                (
                    InnerBoolean::Cuda(CudaBooleanBlock::from_cuda_radix_ciphertext(
                        d_ct.ciphertext,
                    )),
                    cuda_key.tag.clone(),
                )
            }),
        });
        Self::new(ciphertext, tag)
    }
}
