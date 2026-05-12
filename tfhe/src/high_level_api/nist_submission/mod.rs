mod backward_compatibility;
pub mod compact_ciphertext_list;
pub mod parameters;
pub mod prelude;
mod re_randomization;
#[cfg(test)]
mod test;

pub use crate::core_crypto::prelude::NormalizedHammingWeightBound;

#[cfg(feature = "zk-pok")]
pub use compact_ciphertext_list::ProvenCompactCiphertextList;
pub use compact_ciphertext_list::{CompactCiphertextList, CompactCiphertextListBuilder};
pub use parameters::*;
pub use re_randomization::{preproc_eval, NistSubmissionReRandomize};

// ZK proof types
#[cfg(feature = "zk-pok")]
pub use crate::zk::{CompactPkeCrs, ZkComputeLoad};

// Config
pub use crate::high_level_api::config::{Config, ConfigBuilder};

// Keys
#[cfg(feature = "gpu")]
pub use crate::high_level_api::keys::CudaServerKey;
pub use crate::high_level_api::keys::{
    ClientKey, CompactPublicKey, CompressedCompactPublicKey, CompressedReRandomizationKey,
    CompressedReRandomizationKeySwitchingKey, CompressedServerKey, ServerKey,
};
pub use crate::high_level_api::xof_key_set::{CompressedXofKeySet, XofKeySet};

// Global state
#[cfg(feature = "gpu")]
pub use crate::core_crypto::gpu::vec::GpuIndex;
pub use crate::high_level_api::global_state::{set_server_key, unset_server_key};
#[cfg(feature = "gpu")]
pub use crate::high_level_api::global_state::{CudaGpuChoice, CustomMultiGpuIndexes};

// Booleans
pub use crate::high_level_api::booleans::{
    CompressedFheBool, CompressedFheBoolConformanceParams, FheBool, FheBoolConformanceParams,
    SquashedNoiseFheBool,
};

// Integer ID / trait types
pub use crate::high_level_api::integers::{FheIntId, FheIntegerType, FheUintId, IntegerId};

// Generic integer types
pub use crate::high_level_api::integers::{
    CompressedFheInt, CompressedFheUint, FheInt, FheUint, SquashedNoiseFheInt, SquashedNoiseFheUint,
};

// Standard FheUint/FheInt concrete types
expand_pub_use_fhe_type!(
    pub use crate::high_level_api::integers{
        FheUint2, FheUint4, FheUint6, FheUint8, FheUint10, FheUint12, FheUint14, FheUint16,
        FheUint32, FheUint64, FheUint128, FheUint160, FheUint256, FheUint512, FheUint1024,
        FheUint2048,

        FheInt2, FheInt4, FheInt6, FheInt8, FheInt10, FheInt12, FheInt14, FheInt16, FheInt32,
        FheInt64, FheInt128, FheInt160, FheInt256, FheInt512, FheInt1024, FheInt2048,
    };
);

// Extended FheUint/FheInt concrete types
#[cfg(feature = "extended-types")]
expand_pub_use_fhe_type!(
    pub use crate::high_level_api::integers{
        FheUint24, FheUint40, FheUint48, FheUint56, FheUint72, FheUint80, FheUint88, FheUint96,
        FheUint104, FheUint112, FheUint120, FheUint136, FheUint144, FheUint152, FheUint168,
        FheUint176, FheUint184, FheUint192, FheUint200, FheUint208, FheUint216, FheUint224,
        FheUint232, FheUint240, FheUint248,

        FheInt24, FheInt40, FheInt48, FheInt56, FheInt72, FheInt80, FheInt88, FheInt96, FheInt104,
        FheInt112, FheInt120, FheInt136, FheInt144, FheInt152, FheInt168, FheInt176, FheInt184,
        FheInt192, FheInt200, FheInt208, FheInt216, FheInt224, FheInt232, FheInt240, FheInt248,
    };
);

// Compact list helpers
pub use crate::high_level_api::compact_list::{CompactCiphertextListExpander, HlCompactable};

// Compressed ciphertext list
pub use crate::high_level_api::compressed_ciphertext_list::{
    CompressedCiphertextList, CompressedCiphertextListBuilder, HlCompressible, HlExpandable,
};

// Noise squashing
pub use crate::high_level_api::compressed_noise_squashed_ciphertext_list::{
    CompressedSquashedNoiseCiphertextList, CompressedSquashedNoiseCiphertextListBuilder,
    HlSquashedNoiseCompressible, HlSquashedNoiseExpandable,
};

// Serialization
pub use crate::safe_serialization::{DeserializationConfig, SerializationConfig};

// KV Store
pub use crate::high_level_api::kv_store::{CompressedKVStore, KVStore};

// Misc primitives
pub use crate::core_crypto::commons::math::random::{Seed, XofSeed};
pub use crate::high_level_api::integers::oprf::RangeForRandom;
pub use crate::high_level_api::tag::Tag;
pub use crate::high_level_api::traits::FheId;
pub use crate::high_level_api::{Device, FheTypes};
pub use crate::integer::parameters::CompactCiphertextListConformanceParams;
pub use crate::integer::server_key::MatchValues;
