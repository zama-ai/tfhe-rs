use strum::Display;

use crate::traits::{SpecLeafNode, SpecNode};

#[derive(Debug, Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum MsmBench {
    G1(MsmFlavor),
    G2(MsmFlavor),
}

impl SpecNode for MsmBench {
    fn child(&self) -> Option<&dyn SpecNode> {
        Some(match self {
            MsmBench::G1(op) => op,
            MsmBench::G2(op) => op,
        })
    }
}

impl MsmBench {
    pub fn display_name(&self) -> String {
        match self {
            MsmBench::G1(flavor) => format!("MSM_{}_G1", flavor.display_name()),
            MsmBench::G2(flavor) => format!("MSM_{}_G2", flavor.display_name()),
        }
    }
}

#[derive(Debug, Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum MsmFlavor {
    Bls12_446,
}

impl SpecLeafNode for MsmFlavor {}

impl MsmFlavor {
    fn display_name(&self) -> &'static str {
        match self {
            MsmFlavor::Bls12_446 => "BLS12_446",
        }
    }
}
