pub mod keyswitch;

use std::str::FromStr;

use strum::{Display, EnumDiscriminants, EnumString};

use crate::error::SpecParseError;
use crate::traits::SpecNode;
pub use keyswitch::{KsIndices, KsVariant};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Display, EnumDiscriminants, enum_iterator::Sequence,
)]
#[strum(serialize_all = "snake_case")]
#[strum_discriminants(
    name(CoreCryptoBenchKind),
    derive(EnumString, Display),
    strum(serialize_all = "snake_case")
)]
pub enum CoreCryptoBench {
    // ks_bench.rs
    /// `None` on CPU, which has a single implementation.
    Keyswitch(Option<KsVariant>),
    PackingKeyswitch,
    ParPackingKeyswitch,
    // pbs_bench.rs
    PbsMemOptimized,
    BatchedPbsMemOptimized,
    MultiBitPbs,
    MultiBitDeterministicPbs,
    PbsNtt,
    // ks_pbs_bench.rs
    KsPbs,
    MultiBitKsPbs,
    MultiBitDeterministicKsPbs,
    // pbs128_bench.rs
    Pbs128,
    MultiBitPbs128,
}

impl SpecNode for CoreCryptoBench {
    fn child(&self) -> Option<&dyn SpecNode> {
        match self {
            CoreCryptoBench::Keyswitch(Some(variant)) => Some(variant),
            CoreCryptoBench::Keyswitch(None)
            | CoreCryptoBench::PackingKeyswitch
            | CoreCryptoBench::ParPackingKeyswitch
            | CoreCryptoBench::PbsMemOptimized
            | CoreCryptoBench::BatchedPbsMemOptimized
            | CoreCryptoBench::MultiBitPbs
            | CoreCryptoBench::MultiBitDeterministicPbs
            | CoreCryptoBench::PbsNtt
            | CoreCryptoBench::KsPbs
            | CoreCryptoBench::MultiBitKsPbs
            | CoreCryptoBench::MultiBitDeterministicKsPbs
            | CoreCryptoBench::Pbs128
            | CoreCryptoBench::MultiBitPbs128 => None,
        }
    }
}

impl FromStr for CoreCryptoBench {
    type Err = SpecParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (head, rest) = s.split_once("::").unwrap_or((s, ""));
        let kind = CoreCryptoBenchKind::from_str(head)
            .map_err(|_| SpecParseError::Unknown(format!("unknown core_crypto bench: {head}")))?;
        match kind {
            CoreCryptoBenchKind::Keyswitch if rest.is_empty() => Ok(Self::Keyswitch(None)),
            CoreCryptoBenchKind::Keyswitch => Ok(Self::Keyswitch(Some(rest.parse()?))),
            _ if !rest.is_empty() => Err(SpecParseError::Unknown(format!(
                "unexpected {rest:?} after core_crypto bench {head}"
            ))),
            CoreCryptoBenchKind::PackingKeyswitch => Ok(Self::PackingKeyswitch),
            CoreCryptoBenchKind::ParPackingKeyswitch => Ok(Self::ParPackingKeyswitch),
            CoreCryptoBenchKind::PbsMemOptimized => Ok(Self::PbsMemOptimized),
            CoreCryptoBenchKind::BatchedPbsMemOptimized => Ok(Self::BatchedPbsMemOptimized),
            CoreCryptoBenchKind::MultiBitPbs => Ok(Self::MultiBitPbs),
            CoreCryptoBenchKind::MultiBitDeterministicPbs => Ok(Self::MultiBitDeterministicPbs),
            CoreCryptoBenchKind::PbsNtt => Ok(Self::PbsNtt),
            CoreCryptoBenchKind::KsPbs => Ok(Self::KsPbs),
            CoreCryptoBenchKind::MultiBitKsPbs => Ok(Self::MultiBitKsPbs),
            CoreCryptoBenchKind::MultiBitDeterministicKsPbs => Ok(Self::MultiBitDeterministicKsPbs),
            CoreCryptoBenchKind::Pbs128 => Ok(Self::Pbs128),
            CoreCryptoBenchKind::MultiBitPbs128 => Ok(Self::MultiBitPbs128),
        }
    }
}
