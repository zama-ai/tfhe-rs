pub use base::{FheUint, FheUintId};

expand_pub_use_fhe_type!(
    pub use static_{
        FheUint2, FheUint4, FheUint6, FheUint8, FheUint10, FheUint12, FheUint14, FheUint16,
        FheUint32, FheUint64, FheUint128, FheUint160, FheUint256, FheUint2048
    };
);

pub use compact::{CompactFheUint, CompactFheUintList};
pub use compressed::CompressedFheUint;

mod base;
mod compact;
mod compressed;
mod static_;
mod wopbs;

mod encrypt;
mod inner;
mod ops;
mod overflowing_ops;
pub(crate) mod scalar_ops;
#[cfg(test)]
mod tests;
#[cfg(feature = "zk-pok-experimental")]
mod zk;
