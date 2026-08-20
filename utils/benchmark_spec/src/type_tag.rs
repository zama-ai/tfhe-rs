//! The type tag: the free slot of a bench id, closed into an enum.
//!
//! The spec is the only author of these spellings. A benchmark supplies the
//! values, never the text, so there is no second implementation to drift from.

use std::fmt;
use std::str::FromStr;

use crate::error::SpecParseError;

/// A ciphertext or clear-text integer type, as the benches name them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FheType {
    /// `FheUint64`
    Uint(u32),
    /// `FheInt32`
    Int(u32),
    /// A clear-text integer: `u64`, `i32`.
    Clear { signed: bool, bits: u32 },
}

impl fmt::Display for FheType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Uint(bits) => write!(f, "FheUint{bits}"),
            Self::Int(bits) => write!(f, "FheInt{bits}"),
            Self::Clear { signed, bits } => {
                write!(f, "{}{bits}", if signed { 'i' } else { 'u' })
            }
        }
    }
}

impl FromStr for FheType {
    type Err = SpecParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bits = |digits: &str| digits.parse::<u32>().ok();

        if let Some(n) = s.strip_prefix("FheUint").and_then(bits) {
            return Ok(Self::Uint(n));
        }
        if let Some(n) = s.strip_prefix("FheInt").and_then(bits) {
            return Ok(Self::Int(n));
        }
        for (prefix, signed) in [("u", false), ("i", true)] {
            if let Some(n) = s.strip_prefix(prefix).and_then(bits) {
                return Ok(Self::Clear { signed, bits: n });
            }
        }
        Err(SpecParseError::Unknown(format!("unknown type: {s:?}")))
    }
}

/// How wide the operands of a benchmark are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PrecisionTag {
    /// `{n}_bits`
    Bits(usize),
    /// `{n}_bits_scalar_{n}`
    BitsScalar(usize),
    /// `{from}_to_{to}`, a cast between two widths.
    Conversion { from: usize, to: usize },
}

impl fmt::Display for PrecisionTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Bits(n) => write!(f, "{n}_bits"),
            Self::BitsScalar(n) => write!(f, "{n}_bits_scalar_{n}"),
            Self::Conversion { from, to } => write!(f, "{from}_to_{to}"),
        }
    }
}

impl FromStr for PrecisionTag {
    type Err = SpecParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let unknown = || SpecParseError::Unknown(format!("unknown precision: {s:?}"));

        if let Some((head, scalar)) = s.split_once("_bits_scalar_") {
            let bits: usize = head.parse().map_err(|_| unknown())?;
            // `Display` writes the same number twice; a mismatch is not this tag.
            if Some(bits) == scalar.parse().ok() {
                return Ok(Self::BitsScalar(bits));
            }
            return Err(unknown());
        }
        if let Some(n) = s.strip_suffix("_bits") {
            return Ok(Self::Bits(n.parse().map_err(|_| unknown())?));
        }
        let (from, to) = s.split_once("_to_").ok_or_else(unknown)?;
        Ok(Self::Conversion {
            from: from.parse().map_err(|_| unknown())?,
            to: to.parse().map_err(|_| unknown())?,
        })
    }
}

/// The shape of a CUDA keyswitch benchmark.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CudaKeyswitchConfig {
    pub bits: u32,
    pub uses_gemm: Option<bool>,
    pub trivial_indices: Option<bool>,
}

impl CudaKeyswitchConfig {
    pub fn new(bits: u32, uses_gemm: Option<bool>, trivial_indices: Option<bool>) -> Self {
        Self {
            bits,
            uses_gemm,
            trivial_indices,
        }
    }
}

impl fmt::Display for CudaKeyswitchConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}b", self.bits)?;
        if let Some(uses_gemm) = self.uses_gemm {
            f.write_str(if uses_gemm { "::gemm" } else { "::classical" })?;
        }
        if let Some(trivial) = self.trivial_indices {
            f.write_str(if trivial {
                "::trivial_indices"
            } else {
                "::complex_indices"
            })?;
        }
        Ok(())
    }
}

impl FromStr for CudaKeyswitchConfig {
    type Err = SpecParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let unknown = || SpecParseError::Unknown(format!("unknown keyswitch config: {s:?}"));

        let mut segments = s.split("::");
        let bits = segments
            .next()
            .and_then(|head| head.strip_suffix('b'))
            .and_then(|digits| digits.parse().ok())
            .ok_or_else(unknown)?;

        let mut config = Self::new(bits, None, None);
        for segment in segments {
            match segment {
                "gemm" => config.uses_gemm = Some(true),
                "classical" => config.uses_gemm = Some(false),
                "trivial_indices" => config.trivial_indices = Some(true),
                "complex_indices" => config.trivial_indices = Some(false),
                _ => return Err(unknown()),
            }
        }
        Ok(config)
    }
}

/// The two widths a shuffle benchmark is measured at: the values being
/// shuffled, and the keys they are shuffled by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ShuffleConfig {
    pub value_bits: u32,
    pub key_bits: u32,
}

impl fmt::Display for ShuffleConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}_bits::key_{}_bits", self.value_bits, self.key_bits)
    }
}

impl FromStr for ShuffleConfig {
    type Err = SpecParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let unknown = || SpecParseError::Unknown(format!("unknown shuffle config: {s:?}"));

        let (values, keys) = s.split_once("::").ok_or_else(unknown)?;
        let value_bits = values.strip_suffix("_bits").ok_or_else(unknown)?;
        let key_bits = keys
            .strip_prefix("key_")
            .and_then(|bits| bits.strip_suffix("_bits"))
            .ok_or_else(unknown)?;

        Ok(Self {
            value_bits: value_bits.parse().map_err(|_| unknown())?,
            key_bits: key_bits.parse().map_err(|_| unknown())?,
        })
    }
}

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
        ];

        for tag in tags {
            let rendered = tag.to_string();
            let reparsed: TypeTag = rendered
                .parse()
                .unwrap_or_else(|e| panic!("parsing back {rendered:?}: {e:?}"));
            assert_eq!(reparsed, tag, "round-trip mismatch on {rendered:?}");
        }
    }

    /// A ciphertext type and a clear one are told apart by their prefix.
    #[test]
    fn ciphertext_types_are_not_read_as_clear_ones() {
        assert_eq!("FheUint64".parse::<FheType>().unwrap(), FheType::Uint(64));
        assert_eq!(
            "u64".parse::<FheType>().unwrap(),
            FheType::Clear {
                signed: false,
                bits: 64
            }
        );
    }

    /// `Display` writes the number twice, so a mismatch is not this tag.
    #[test]
    fn scalar_precision_is_not_read_as_plain_bits() {
        assert_eq!(
            "32_bits_scalar_32".parse::<PrecisionTag>().unwrap(),
            PrecisionTag::BitsScalar(32)
        );
        // Two different numbers were never rendered by `Display`.
        assert!("32_bits_scalar_64".parse::<PrecisionTag>().is_err());
    }

    /// The tag set is closed: an unknown shape is an error, not a fallback.
    #[test]
    fn unknown_shapes_are_rejected() {
        for s in ["", "whatever", "32b::nonsense", "key_x::not_a_value"] {
            assert!(s.parse::<TypeTag>().is_err(), "{s:?} should not parse");
        }
    }
}
