use std::fmt;
use std::str::FromStr;

use crate::error::SpecParseError;

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
