mod base;
mod compact;
mod compressed;

mod encrypt;
mod inner;
mod ops;
mod overflowing_ops;
mod scalar_ops;
mod static_;
#[cfg(test)]
mod tests;
#[cfg(feature = "zk-pok-experimental")]
mod zk;

pub use base::{FheInt, FheIntId};
pub use compact::{CompactFheInt, CompactFheIntList};
pub use compressed::CompressedFheInt;

expand_pub_use_fhe_type!(
    pub use static_{
        FheInt2, FheInt4, FheInt6, FheInt8, FheInt10, FheInt12, FheInt14, FheInt16,
        FheInt32, FheInt64, FheInt128, FheInt160, FheInt256
    };
);
