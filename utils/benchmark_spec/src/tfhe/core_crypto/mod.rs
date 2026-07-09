use strum::Display;

use crate::traits::SpecLeafNode;

#[derive(Debug, Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum CoreCryptoBench {
    // ks_bench.rs
    Keyswitch,
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

impl SpecLeafNode for CoreCryptoBench {}
