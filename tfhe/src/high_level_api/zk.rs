use crate::core_crypto::prelude::LweCiphertextCount;
use crate::zk::CompactPkeCrs;
use crate::{Config, Error};

impl CompactPkeCrs {
    /// Create a new `CompactPkeCrs` from a `Config` object.
    /// max_bit_size is the maximum number of bits that can be proven, e.g. 64 for a single
    /// FheUint64 or 8 x FheUint8 values.
    ///
    /// This function assumes that packing will be applied during ZK proof.
    pub fn from_config(config: Config, max_bit_size: usize) -> crate::Result<Self> {
        let compact_encryption_parameters = config.public_key_encryption_parameters()?;

        if compact_encryption_parameters.carry_modulus.0
            < compact_encryption_parameters.message_modulus.0
        {
            return Err(Error::new(
                "In order to build a ZK-CRS for packed compact ciphertext list encryption, \
                parameters must have CarryModulus >= MessageModulus"
                    .to_string(),
            ));
        }

        let carry_and_message_bit_capacity = (compact_encryption_parameters.carry_modulus.0
            * compact_encryption_parameters.message_modulus.0)
            .ilog2() as usize;
        let max_num_message = max_bit_size.div_ceil(carry_and_message_bit_capacity);
        let crs = Self::from_shortint_params(
            compact_encryption_parameters,
            LweCiphertextCount(max_num_message),
        )?;
        Ok(crs)
    }
}
