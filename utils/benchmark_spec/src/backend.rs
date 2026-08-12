use serde::{Deserialize, Serialize};
use strum::{Display, EnumString, IntoStaticStr};

#[derive(
    Debug,
    Clone,
    Copy,
    Display,
    Deserialize,
    EnumString,
    Serialize,
    PartialEq,
    Eq,
    Hash,
    IntoStaticStr,
)]
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
