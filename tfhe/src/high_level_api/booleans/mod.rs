pub use base::{FheBool, FheBoolConformanceParams};
pub use compact::{CompactFheBool, CompactFheBoolList, CompactFheBoolListConformanceParams};
pub use compressed::CompressedFheBool;

mod base;
mod compact;
mod compressed;
mod encrypt;
mod inner;
#[cfg(test)]
mod tests;
