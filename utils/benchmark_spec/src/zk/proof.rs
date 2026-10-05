use std::fmt;
use std::str::FromStr;

use strum::{Display, EnumDiscriminants, EnumString};

use crate::error::SpecParseError;
use crate::traits::{SpecLeafNode, SpecNode};

/// Spelled with its prefix: `verify::v2::verify` would read as a typo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display, EnumString, enum_iterator::Sequence)]
pub enum ComputeLoad {
    #[strum(serialize = "compute_load_proof")]
    Proof,
    #[strum(serialize = "compute_load_verify")]
    Verify,
}

impl SpecLeafNode for ComputeLoad {}

/// Same proof, computed by another implementation. Absent for the default
/// `tfhe-zk-pok` one, whatever the backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display, EnumString, enum_iterator::Sequence)]
#[strum(serialize_all = "snake_case")]
pub enum ZkAcceleration {
    /// `tfhe_zk_pok::gpu`, picked by `tfhe` when built with `gpu-zk`.
    GpuZk,
}

impl SpecLeafNode for ZkAcceleration {}

/// Only v2 has an accelerated implementation, so only v2 can carry one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, enum_iterator::Sequence)]
pub struct ZkV2Load {
    pub compute_load: ComputeLoad,
    pub acceleration: Option<ZkAcceleration>,
}

impl fmt::Display for ZkV2Load {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.compute_load)
    }
}

impl SpecNode for ZkV2Load {
    fn child(&self) -> Option<&dyn SpecNode> {
        self.acceleration
            .as_ref()
            .map(|acceleration| acceleration as &dyn SpecNode)
    }
}

impl FromStr for ZkV2Load {
    type Err = SpecParseError;

    /// Rejects anything after the load that is not an acceleration, so the
    /// longest-prefix split of the id does not swallow the backend.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (compute_load, acceleration) = match s.split_once("::") {
            Some((load, acceleration)) => (load, Some(acceleration.parse()?)),
            None => (s, None),
        };
        Ok(Self {
            compute_load: compute_load.parse()?,
            acceleration,
        })
    }
}

/// [`ZkScheme`] is its discriminant.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Display, EnumDiscriminants, enum_iterator::Sequence,
)]
#[strum(serialize_all = "snake_case")]
#[strum_discriminants(
    name(ZkScheme),
    derive(EnumString, Display, Hash, enum_iterator::Sequence),
    strum(serialize_all = "snake_case")
)]
pub enum ZkProofVariant {
    V1(ComputeLoad),
    V2(ZkV2Load),
}

impl SpecLeafNode for ZkScheme {}

impl ZkProofVariant {
    pub const fn new(scheme: ZkScheme, compute_load: ComputeLoad) -> Self {
        match scheme {
            ZkScheme::V1 => Self::V1(compute_load),
            ZkScheme::V2 => Self::V2(ZkV2Load {
                compute_load,
                acceleration: None,
            }),
        }
    }

    /// v1 has no accelerated implementation and is returned unchanged.
    pub const fn with_acceleration(self, acceleration: ZkAcceleration) -> Self {
        match self {
            Self::V1(_) => self,
            Self::V2(load) => Self::V2(ZkV2Load {
                acceleration: Some(acceleration),
                ..load
            }),
        }
    }

    pub fn compute_load(&self) -> ComputeLoad {
        match *self {
            Self::V1(load) => load,
            Self::V2(load) => load.compute_load,
        }
    }
}

impl SpecNode for ZkProofVariant {
    fn child(&self) -> Option<&dyn SpecNode> {
        Some(match self {
            Self::V1(load) => load,
            Self::V2(load) => load,
        })
    }
}

impl FromStr for ZkProofVariant {
    type Err = SpecParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (head, rest) = s.split_once("::").unwrap_or((s, ""));
        match ZkScheme::from_str(head)
            .map_err(|_| SpecParseError::Unknown(format!("unknown zk scheme: {head}")))?
        {
            ZkScheme::V1 => Ok(Self::V1(rest.parse()?)),
            ZkScheme::V2 => Ok(Self::V2(rest.parse()?)),
        }
    }
}
