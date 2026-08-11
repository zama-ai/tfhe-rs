use std::fmt;
use std::str::FromStr;

use strum::{Display, EnumDiscriminants, EnumString};

use crate::error::SpecParseError;
use crate::tfhe::TfheLayer;
use crate::traits::write_spec;
use crate::zk::ZkLayer;

#[derive(Debug, Clone, Copy, EnumDiscriminants, enum_iterator::Sequence)]
#[strum_discriminants(
    name(BenchCrateKind),
    derive(EnumString, Display),
    strum(serialize_all = "snake_case")
)]
pub enum BenchCrate {
    Tfhe(TfheLayer),
    Zk(ZkLayer),
}

impl FromStr for BenchCrate {
    type Err = SpecParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (head, rest) = s.split_once("::").unwrap_or((s, ""));
        match BenchCrateKind::from_str(head)
            .map_err(|_| SpecParseError::Unknown(format!("unknown bench crate: {head}")))?
        {
            BenchCrateKind::Tfhe => Ok(Self::Tfhe(rest.parse()?)),
            BenchCrateKind::Zk => Ok(Self::Zk(rest.parse()?)),
        }
    }
}

impl fmt::Display for BenchCrate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Crate token ("tfhe" / "zk") from the discriminant, then the layer tree.
        write!(f, "{}", BenchCrateKind::from(self))?;
        match self {
            BenchCrate::Tfhe(layer) => write_spec(layer, f),
            BenchCrate::Zk(layer) => write_spec(layer, f),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every possible path must survive a `Display -> FromStr -> Display`
    /// round-trip.
    #[test]
    fn roundtrip_all_bench_paths() {
        for bc in enum_iterator::all::<BenchCrate>() {
            let s = bc.to_string();
            let reparsed = s
                .parse::<BenchCrate>()
                .unwrap_or_else(|e| panic!("parse of {s:?} failed: {e:?}"));
            assert_eq!(reparsed.to_string(), s, "round-trip mismatch for {s:?}");
        }
    }
}
