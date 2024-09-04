pub use base::{FheBool, FheBoolConformanceParams};
pub use compressed::CompressedFheBool;

pub(in crate::high_level_api) use compressed::InnerCompressedFheBool;
pub(in crate::high_level_api) use inner::{InnerBoolean, InnerBooleanVersionOwned};

mod base;
mod compressed;
mod encrypt;
mod inner;
#[cfg(test)]
mod tests;
