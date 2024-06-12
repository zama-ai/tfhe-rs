pub use base::{FheBool, FheBoolConformanceParams};
pub use compressed::CompressedFheBool;

pub(in crate::high_level_api) use inner::InnerBooleanVersionOwned;

mod base;
mod compressed;
mod encrypt;
mod inner;
#[cfg(test)]
mod tests;
