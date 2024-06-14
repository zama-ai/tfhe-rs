use crate::zk::CompactPkeCrs;
use crate::Config;

impl CompactPkeCrs {
    /// Create a new `CompactPkeCrs` from a `Config` object.
    /// max_bit_size is the maximum number of bits that can be proven, e.g. 64 for a single
    /// FheUint64 or 8 x FheUint8 values.
    pub fn from_config(config: Config, max_bit_size: usize) -> crate::Result<Self> {
        let compact_encryption_parameters = config.public_key_encryption_parameters()?;

        let max_num_message =
            max_bit_size / compact_encryption_parameters.message_modulus.0.ilog2() as usize;
        let crs = Self::from_shortint_params(&compact_encryption_parameters, max_num_message)?;
        Ok(crs)
    }
}
