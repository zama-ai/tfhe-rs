expand_pub_use_fhe_type!(
    pub use types{
        FheUint8, FheUint10, FheUint12, FheUint14, FheUint16, FheUint32, FheUint64, FheUint128,
        FheUint256, FheInt8, FheInt16, FheInt32, FheInt64, FheInt128, FheInt256
    };
);

pub(in crate::high_level_api) use keys::{
    IntegerClientKey, IntegerCompactPublicKey, IntegerCompressedCompactPublicKey,
    IntegerCompressedServerKey, IntegerConfig, IntegerServerKey,
};

mod client_key;
mod keys;
mod parameters;
mod server_key;
#[cfg(test)]
mod tests_signed;
#[cfg(test)]
mod tests_unsigned;
mod types;
