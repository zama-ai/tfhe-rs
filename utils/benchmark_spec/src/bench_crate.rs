use std::fmt;
use strum::Display;

use crate::tfhe::TfheLayer;
use crate::traits::SpecFmt;

#[derive(Display)]
#[strum(serialize_all = "snake_case")]
pub enum BenchCrate {
    Tfhe(TfheLayer),
}

impl BenchCrate {
    fn layer(&self) -> &dyn SpecFmt {
        match self {
            BenchCrate::Tfhe(layer) => layer,
        }
    }

    pub(crate) fn fmt_crate(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")?;
        self.layer().fmt_spec(f)
    }
}
