//! The tag of a compact public key encryption proof benchmark.

use std::fmt;
use std::str::FromStr;

use crate::error::SpecParseError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ZkPkeConfig {
    /// `None` for the CRS, whose size does not depend on it.
    pub bits_packed: Option<u32>,
    pub crs_bits: u32,
}

impl fmt::Display for ZkPkeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(bits_packed) = self.bits_packed {
            write!(f, "{bits_packed}_bits_packed::")?;
        }
        write!(f, "{}_bits_crs", self.crs_bits)
    }
}

impl FromStr for ZkPkeConfig {
    type Err = SpecParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let unknown = || SpecParseError::Unknown(format!("unknown zk pke config: {s:?}"));

        let (bits_packed, crs) = match s.split_once("::") {
            Some((packed, crs)) => (Some(packed), crs),
            None => (None, s),
        };
        let bits_packed = bits_packed
            .map(|packed| {
                packed
                    .strip_suffix("_bits_packed")
                    .and_then(|bits| bits.parse().ok())
                    .ok_or_else(unknown)
            })
            .transpose()?;
        let crs_bits = crs
            .strip_suffix("_bits_crs")
            .and_then(|bits| bits.parse().ok())
            .ok_or_else(unknown)?;

        Ok(Self {
            bits_packed,
            crs_bits,
        })
    }
}
