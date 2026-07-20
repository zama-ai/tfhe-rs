pub mod msm;

use strum::Display;

use crate::traits::SpecNode;
use msm::MsmBench;

#[derive(Debug, Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum ZkLayer {
    Msm(MsmBench),
}

impl SpecNode for ZkLayer {
    fn child(&self) -> Option<&dyn SpecNode> {
        Some(match self {
            ZkLayer::Msm(bench) => bench,
        })
    }
}
