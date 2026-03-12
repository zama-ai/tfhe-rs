use std::fmt;
use strum::Display;

use super::backend::Backend;
use super::layer::TfheLayer;

#[derive(Display)]
#[strum(serialize_all = "snake_case")]
pub enum BenchCrate {
    Tfhe(TfheLayer),
}

impl BenchCrate {
    fn layer(&self) -> &TfheLayer {
        match self {
            BenchCrate::Tfhe(layer) => layer,
        }
    }

    pub(crate) fn fmt_with_backend(
        &self,
        f: &mut fmt::Formatter<'_>,
        backend: &Backend,
    ) -> fmt::Result {
        write!(f, "{self}::")?;
        self.layer().fmt_with_backend(f, backend)
    }
}
