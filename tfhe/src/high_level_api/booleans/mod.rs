pub use base::{FheBool, FheBoolConformanceParams};
pub use compact::{
    CompactFheBool, CompactFheBoolConformanceParams, CompactFheBoolList,
    CompactFheBoolListConformanceParams,
};
pub use compressed::{CompressedFheBool, CompressedFheBoolConformanceParams};

mod base;
mod compact;
mod compressed;
mod encrypt;
mod inner;
#[cfg(test)]
mod tests;
