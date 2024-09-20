use super::FheBool;
use crate::high_level_api::global_state;
use crate::high_level_api::keys::InternalServerKey;
use crate::integer::BooleanBlock;
use concrete_csprng::seeders::Seed;

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
        global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                let ct = key.pbs_key().key.generate_oblivious_pseudo_random(seed, 1);

                Self::new(BooleanBlock(ct), key.tag.clone())
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                todo!("Cuda devices do not yet support oblivious pseudo random generation")
            }
        })
    }
}
