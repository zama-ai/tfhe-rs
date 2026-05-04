use std::str::FromStr;

use serde::{Deserialize, Serialize};
use strum::Display;

#[derive(Debug, Clone, Copy, Display, Deserialize, Serialize)]
#[strum(serialize_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    Cpu,
    Cuda,
    Hpu,
}

pub fn bench_backend_from_cfg() -> Backend {
    if cfg!(feature = "gpu") {
        Backend::Cuda
    } else if cfg!(feature = "hpu") {
        Backend::Hpu
    } else {
        Backend::Cpu
    }
}

impl FromStr for Backend {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "cpu" => Ok(Self::Cpu),
            "cuda" => Ok(Self::Cuda),
            "hpu" => Ok(Self::Hpu),
            _ => Err(format!("unknown benchmark metric: {s}")),
        }
    }
}
