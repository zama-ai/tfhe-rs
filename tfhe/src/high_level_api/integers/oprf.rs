use super::{FheIntId, FheUintId};
use crate::high_level_api::global_state;
use crate::high_level_api::keys::InternalServerKey;
use crate::integer::oprf::SignedRandomizationSpec;
use crate::{FheInt, FheUint, Seed};

impl<Id: FheUintId> FheUint<Id> {
    /// Generates an encrypted `num_block` blocks unsigned integer
    /// taken uniformly in `[0, 2^random_bits_count[` using the given seed
    /// The encryted value is oblivious to the server
    /// It can be useful to make server random generation deterministic
    ///
    /// ```rust
    /// use tfhe::prelude::FheDecrypt;
    /// use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint8, Seed};
    ///
    /// let config = ConfigBuilder::default().build();
    /// let (client_key, server_key) = generate_keys(config);
    ///
    /// set_server_key(server_key);
    ///
    /// let random_bits_count = 3;
    ///
    /// let ct_res = FheUint8::generate_oblivious_pseudo_random(Seed(0), random_bits_count);
    ///
    /// let dec_result: u16 = ct_res.decrypt(&client_key);
    /// assert!(dec_result < (1 << random_bits_count));
    /// ```
    pub fn generate_oblivious_pseudo_random(seed: Seed, random_bits_count: u64) -> Self {
        let ct = global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => key
                .key
                .par_generate_oblivious_pseudo_random_unsigned_integer(
                    seed,
                    random_bits_count,
                    Id::num_blocks(key.message_modulus()) as u64,
                ),
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                todo!("Cuda devices do not yet support oblivious pseudo random generation")
            }
        });

        Self::new(ct)
    }
}

impl<Id: FheIntId> FheInt<Id> {
    /// Generates an encrypted `num_block` blocks signed integer
    /// using the given seed following the randomizer spec
    /// The encryted value is oblivious to the server
    /// It can be useful to make server random generation deterministic
    ///
    /// ```rust
    /// use tfhe::prelude::FheDecrypt;
    /// use tfhe::{
    ///     generate_keys, set_server_key, ConfigBuilder, FheInt8, Seed, SignedRandomizationSpec,
    /// };
    ///
    /// let config = ConfigBuilder::default().build();
    /// let (client_key, server_key) = generate_keys(config);
    ///
    /// set_server_key(server_key);
    ///
    /// let ct_res =
    ///     FheInt8::generate_oblivious_pseudo_random(Seed(0), SignedRandomizationSpec::FullSigned);
    ///
    /// let dec_result: i16 = ct_res.decrypt(&client_key);
    /// assert!(dec_result < 1 << 7);
    /// assert!(dec_result >= -(1 << 7));
    /// ```
    pub fn generate_oblivious_pseudo_random(
        seed: Seed,
        randomizer: SignedRandomizationSpec,
    ) -> Self {
        let ct = global_state::with_internal_keys(|key| match key {
            InternalServerKey::Cpu(key) => {
                key.key.par_generate_oblivious_pseudo_random_signed_integer(
                    seed,
                    randomizer,
                    Id::num_blocks(key.message_modulus()) as u64,
                )
            }
            #[cfg(feature = "gpu")]
            InternalServerKey::Cuda(_) => {
                todo!("Cuda devices do not yet support oblivious pseudo random generation")
            }
        });

        Self::new(ct)
    }
}
