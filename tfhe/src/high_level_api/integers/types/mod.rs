pub use base::GenericInteger;

expand_pub_use_fhe_type!(
    pub use static_{
        FheUint8, FheUint10, FheUint12, FheUint14, FheUint16, FheUint32, FheUint64, FheUint128,
        FheUint256, FheInt8, FheInt16, FheInt32, FheInt64, FheInt128, FheInt256
    };
);

pub(super) mod base;
pub(super) mod compact;
pub(super) mod compressed;
pub(super) mod static_;
