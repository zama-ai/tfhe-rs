pub use base::{FheBool, FheBoolConformanceParams};
pub use compact::{CompactFheBool, CompactFheBoolList, CompactFheBoolListConformanceParams};
pub use compressed::CompressedFheBool;
#[cfg(feature = "zk-pok-experimental")]
pub use zk::{ProvenCompactFheBool, ProvenCompactFheBoolList};

mod base;
mod compact;
mod compressed;
mod encrypt;
mod inner;
#[cfg(test)]
mod tests;
#[cfg(feature = "zk-pok-experimental")]
mod zk;
