use std::str::FromStr;

use strum::{Display, EnumDiscriminants, EnumString};

use crate::error::SpecParseError;
use crate::traits::SpecNode;
use crate::zk::proof::ComputeLoad;

/// The proof benches of `tfhe-zk-pok`, run on its primitives directly.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Display, EnumDiscriminants, enum_iterator::Sequence,
)]
#[strum(serialize_all = "snake_case")]
#[strum_discriminants(
    name(PkeBenchKind),
    derive(EnumString, Display),
    strum(serialize_all = "snake_case")
)]
pub enum PkeBench {
    Proof(PkeProof),
    Verify(PkeVerify),
}

impl SpecNode for PkeBench {
    fn child(&self) -> Option<&dyn SpecNode> {
        Some(match self {
            PkeBench::Proof(proof) => proof,
            PkeBench::Verify(verify) => verify,
        })
    }
}

impl FromStr for PkeBench {
    type Err = SpecParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (head, rest) = s.split_once("::").unwrap_or((s, ""));
        match PkeBenchKind::from_str(head)
            .map_err(|_| SpecParseError::Unknown(format!("unknown zk pke bench: {head}")))?
        {
            PkeBenchKind::Proof => Ok(Self::Proof(rest.parse()?)),
            PkeBenchKind::Verify => Ok(Self::Verify(rest.parse()?)),
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Display, EnumDiscriminants, enum_iterator::Sequence,
)]
#[strum(serialize_all = "snake_case")]
#[strum_discriminants(
    name(PkeProofKind),
    derive(EnumString, Display),
    strum(serialize_all = "snake_case")
)]
pub enum PkeProof {
    V1(ComputeLoad),
    V2(ZkBound),
}

impl SpecNode for PkeProof {
    fn child(&self) -> Option<&dyn SpecNode> {
        Some(match self {
            PkeProof::V1(load) => load,
            PkeProof::V2(bound) => bound,
        })
    }
}

impl FromStr for PkeProof {
    type Err = SpecParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (head, rest) = s.split_once("::").unwrap_or((s, ""));
        match PkeProofKind::from_str(head)
            .map_err(|_| SpecParseError::Unknown(format!("unknown zk pke scheme: {head}")))?
        {
            PkeProofKind::V1 => Ok(Self::V1(rest.parse()?)),
            PkeProofKind::V2 => Ok(Self::V2(rest.parse()?)),
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Display, EnumDiscriminants, enum_iterator::Sequence,
)]
#[strum(serialize_all = "snake_case")]
#[strum_discriminants(
    name(PkeVerifyKind),
    derive(EnumString, Display),
    strum(serialize_all = "snake_case")
)]
pub enum PkeVerify {
    V1(ComputeLoad),
    V2(ZkPairingMode),
}

impl SpecNode for PkeVerify {
    fn child(&self) -> Option<&dyn SpecNode> {
        Some(match self {
            PkeVerify::V1(load) => load,
            PkeVerify::V2(mode) => mode,
        })
    }
}

impl FromStr for PkeVerify {
    type Err = SpecParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (head, rest) = s.split_once("::").unwrap_or((s, ""));
        match PkeVerifyKind::from_str(head)
            .map_err(|_| SpecParseError::Unknown(format!("unknown zk pke scheme: {head}")))?
        {
            PkeVerifyKind::V1 => Ok(Self::V1(rest.parse()?)),
            PkeVerifyKind::V2 => Ok(Self::V2(rest.parse()?)),
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Display, EnumDiscriminants, enum_iterator::Sequence,
)]
#[strum(serialize_all = "snake_case")]
#[strum_discriminants(
    name(ZkPairingModeKind),
    derive(EnumString, Display),
    strum(serialize_all = "snake_case")
)]
pub enum ZkPairingMode {
    TwoSteps(ZkBound),
    Batched(ZkBound),
}

impl SpecNode for ZkPairingMode {
    fn child(&self) -> Option<&dyn SpecNode> {
        Some(match self {
            ZkPairingMode::TwoSteps(bound) | ZkPairingMode::Batched(bound) => bound,
        })
    }
}

impl FromStr for ZkPairingMode {
    type Err = SpecParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (head, rest) = s.split_once("::").unwrap_or((s, ""));
        match ZkPairingModeKind::from_str(head)
            .map_err(|_| SpecParseError::Unknown(format!("unknown zk pairing mode: {head}")))?
        {
            ZkPairingModeKind::TwoSteps => Ok(Self::TwoSteps(rest.parse()?)),
            ZkPairingModeKind::Batched => Ok(Self::Batched(rest.parse()?)),
        }
    }
}

/// The noise bound the v2 CRS is built for.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Display, EnumDiscriminants, enum_iterator::Sequence,
)]
#[strum(serialize_all = "snake_case")]
#[strum_discriminants(
    name(ZkBoundKind),
    derive(EnumString, Display),
    strum(serialize_all = "snake_case")
)]
pub enum ZkBound {
    Cs(ComputeLoad),
    Ghl(ComputeLoad),
}

impl SpecNode for ZkBound {
    fn child(&self) -> Option<&dyn SpecNode> {
        Some(match self {
            ZkBound::Cs(load) | ZkBound::Ghl(load) => load,
        })
    }
}

impl FromStr for ZkBound {
    type Err = SpecParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (head, rest) = s.split_once("::").unwrap_or((s, ""));
        match ZkBoundKind::from_str(head)
            .map_err(|_| SpecParseError::Unknown(format!("unknown zk bound: {head}")))?
        {
            ZkBoundKind::Cs => Ok(Self::Cs(rest.parse()?)),
            ZkBoundKind::Ghl => Ok(Self::Ghl(rest.parse()?)),
        }
    }
}
