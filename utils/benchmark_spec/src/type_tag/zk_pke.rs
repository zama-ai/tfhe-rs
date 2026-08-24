//! The tag of a compact public key encryption proof benchmark.
//!
//! The operation itself is named by [`crate::tfhe::integer::zk_pke::ZkPkeBench`];
//! this is only what qualifies one measurement point.

use std::fmt;
use std::str::FromStr;

use strum::{Display, EnumString};

use crate::error::SpecParseError;

/// Which side of a compact public key encryption proof carries the work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum ComputeLoad {
    Proof,
    Verify,
}

/// The zk scheme a parameter set supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display, EnumString)]
#[strum(serialize_all = "snake_case")]
pub enum ZkScheme {
    V1,
    V2,
}

/// The axes a compact public key encryption proof benchmark varies: how many
/// bits are packed into the proven list, how many bits the CRS was built for,
/// which side carries the compute load, and the scheme version.
///
/// Only the two widths are spelled here; the rest is the vocabulary above.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ZkPkeConfig {
    /// `None` for the CRS, whose size does not depend on it.
    pub bits_packed: Option<u32>,
    pub crs_bits: u32,
    /// `None` for the CRS, which is built before a load is chosen.
    pub compute_load: Option<ComputeLoad>,
    pub scheme: ZkScheme,
}

impl fmt::Display for ZkPkeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(bits_packed) = self.bits_packed {
            write!(f, "{bits_packed}_bits_packed::")?;
        }
        write!(f, "{}_bits_crs", self.crs_bits)?;
        if let Some(compute_load) = self.compute_load {
            write!(f, "::compute_load_{compute_load}")?;
        }
        write!(f, "::zk_{}", self.scheme)
    }
}

impl FromStr for ZkPkeConfig {
    type Err = SpecParseError;

    /// Each segment carries its own marker, so they are read by shape rather
    /// than by position: the two optional ones can be absent.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let unknown = || SpecParseError::Unknown(format!("unknown zk pke config: {s:?}"));

        let mut bits_packed = None;
        let mut crs_bits = None;
        let mut compute_load = None;
        let mut scheme = None;

        for segment in s.split("::") {
            if let Some(bits) = segment.strip_suffix("_bits_packed") {
                bits_packed = Some(bits.parse().map_err(|_| unknown())?);
            } else if let Some(bits) = segment.strip_suffix("_bits_crs") {
                crs_bits = Some(bits.parse().map_err(|_| unknown())?);
            } else if let Some(load) = segment.strip_prefix("compute_load_") {
                compute_load = Some(load.parse().map_err(|_| unknown())?);
            } else if let Some(version) = segment.strip_prefix("zk_") {
                scheme = Some(version.parse().map_err(|_| unknown())?);
            } else {
                return Err(unknown());
            }
        }

        Ok(Self {
            bits_packed,
            crs_bits: crs_bits.ok_or_else(unknown)?,
            compute_load,
            scheme: scheme.ok_or_else(unknown)?,
        })
    }
}
