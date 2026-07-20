use std::fmt;
use strum::Display;

use crate::tfhe::TfheLayer;
use crate::traits::write_spec;
use crate::zk::ZkLayer;

#[derive(Debug, Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum BenchCrate {
    Tfhe(TfheLayer),
    Zk(ZkLayer),
}

impl BenchCrate {
    pub(crate) fn fmt_crate(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")?;
        match self {
            BenchCrate::Tfhe(layer) => write_spec(layer, f),
            BenchCrate::Zk(layer) => write_spec(layer, f),
        }
    }
}
