use std::fmt;
use strum::Display;

use crate::traits::SpecFmt;

#[derive(Clone, Copy, Display)]
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

impl CoreCryptoBench {
    fn op(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // All variants are leaf benchmarks — no inner op to format.
        Ok(())
    }
}

impl SpecFmt for CoreCryptoBench {
    fn fmt_spec(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "::{}", self)?;
        self.op(f)
    }
}
