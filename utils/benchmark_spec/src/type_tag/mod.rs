//! The type tag: the free slot of a bench id, closed into an enum.
//!
//! The spec is the only author of these spellings. A benchmark supplies the
//! values, never the text, so there is no second implementation to drift from.
//!
//! One module per shape, and this file for the enum that closes over them.

mod cuda_keyswitch;
mod fhe_type;
mod precision;
mod shuffle;
mod zk_pke;

use std::fmt;
use std::str::FromStr;

use crate::error::SpecParseError;

pub use cuda_keyswitch::CudaKeyswitchConfig;
pub use fhe_type::FheType;
pub use precision::PrecisionTag;
pub use shuffle::ShuffleConfig;
pub use zk_pke::{ComputeLoad, ZkPkeConfig, ZkScheme};

/// Everything the type slot of a bench id can hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TypeTag {
    Precision(PrecisionTag),
    Type(FheType),
    /// `key_{k}::value_{v}`, for the key-value store benches.
    KeyValue {
        key: FheType,
        value: FheType,
    },
    CudaKeyswitch(CudaKeyswitchConfig),
    /// `{v}_bits::key_{k}_bits`, for the shuffle benches.
    Shuffle(ShuffleConfig),
    /// `bound_{n}`, the excluded upper bound of an OPRF range.
    Bound(u64),
    /// `{n}_bits_packed::{n}_bits_crs::compute_load_{load}::zk_{version}`, for
    /// the proven compact list benches.
    ZkPke(ZkPkeConfig),
}

impl fmt::Display for TypeTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Precision(tag) => tag.fmt(f),
            Self::Type(ty) => ty.fmt(f),
            Self::KeyValue { key, value } => write!(f, "key_{key}::value_{value}"),
            Self::CudaKeyswitch(config) => config.fmt(f),
            Self::Shuffle(config) => config.fmt(f),
            Self::Bound(n) => write!(f, "bound_{n}"),
            Self::ZkPke(config) => config.fmt(f),
        }
    }
}

impl FromStr for TypeTag {
    type Err = SpecParseError;

    /// The keyswitch config comes last: it is the fallback, so anything reaching
    /// it and failing is an error rather than another shape.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(n) = s.strip_prefix("bound_") {
            return Ok(Self::Bound(n.parse().map_err(|_| {
                SpecParseError::Unknown(format!("unknown bound: {s:?}"))
            })?));
        }
        if let Some((key, value)) = s.split_once("::")
            && let (Some(key), Some(value)) =
                (key.strip_prefix("key_"), value.strip_prefix("value_"))
        {
            return Ok(Self::KeyValue {
                key: key.parse()?,
                value: value.parse()?,
            });
        }
        // The CRS size is the one segment this config always writes, so the
        // marker commits to it: a malformed rest is an error, not another shape.
        if s.contains("_bits_crs") {
            return Ok(Self::ZkPke(s.parse()?));
        }
        if let Ok(config) = s.parse::<ShuffleConfig>() {
            return Ok(Self::Shuffle(config));
        }
        if let Ok(tag) = s.parse::<PrecisionTag>() {
            return Ok(Self::Precision(tag));
        }
        if let Ok(ty) = s.parse::<FheType>() {
            return Ok(Self::Type(ty));
        }
        Ok(Self::CudaKeyswitch(s.parse()?))
    }
}

impl From<PrecisionTag> for TypeTag {
    fn from(tag: PrecisionTag) -> Self {
        Self::Precision(tag)
    }
}

impl From<FheType> for TypeTag {
    fn from(ty: FheType) -> Self {
        Self::Type(ty)
    }
}

impl From<CudaKeyswitchConfig> for TypeTag {
    fn from(config: CudaKeyswitchConfig) -> Self {
        Self::CudaKeyswitch(config)
    }
}

impl From<ShuffleConfig> for TypeTag {
    fn from(config: ShuffleConfig) -> Self {
        Self::Shuffle(config)
    }
}

impl From<ZkPkeConfig> for TypeTag {
    fn from(config: ZkPkeConfig) -> Self {
        Self::ZkPke(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every tag must render to a string that parses back to it.
    #[test]
    fn every_tag_round_trips() {
        let tags = [
            TypeTag::Precision(PrecisionTag::Bits(64)),
            TypeTag::Precision(PrecisionTag::BitsScalar(32)),
            TypeTag::Precision(PrecisionTag::Conversion { from: 64, to: 64 }),
            TypeTag::Type(FheType::Uint(64)),
            TypeTag::Type(FheType::Int(32)),
            TypeTag::Type(FheType::Clear {
                signed: false,
                bits: 8,
            }),
            TypeTag::KeyValue {
                key: FheType::Uint(32),
                value: FheType::Uint(64),
            },
            TypeTag::CudaKeyswitch(CudaKeyswitchConfig::new(32, None, None)),
            TypeTag::CudaKeyswitch(CudaKeyswitchConfig::new(64, Some(true), Some(false))),
            TypeTag::CudaKeyswitch(CudaKeyswitchConfig::new(64, Some(false), Some(true))),
            TypeTag::Shuffle(ShuffleConfig {
                value_bits: 64,
                key_bits: 16,
            }),
            TypeTag::Bound(52),
            TypeTag::ZkPke(ZkPkeConfig {
                bits_packed: Some(2048),
                crs_bits: 4096,
                compute_load: Some(ComputeLoad::Verify),
                scheme: ZkScheme::V2,
            }),
            // The CRS carries neither the packed width nor the load.
            TypeTag::ZkPke(ZkPkeConfig {
                bits_packed: None,
                crs_bits: 64,
                compute_load: None,
                scheme: ZkScheme::V1,
            }),
        ];

        for tag in tags {
            let rendered = tag.to_string();
            let reparsed: TypeTag = rendered
                .parse()
                .unwrap_or_else(|e| panic!("parsing back {rendered:?}: {e:?}"));
            assert_eq!(reparsed, tag, "round-trip mismatch on {rendered:?}");
        }
    }

    /// The tag set is closed: an unknown shape is an error, not a fallback.
    #[test]
    fn unknown_shapes_are_rejected() {
        for s in ["", "whatever", "32b::nonsense", "key_x::not_a_value"] {
            assert!(s.parse::<TypeTag>().is_err(), "{s:?} should not parse");
        }
    }
}
