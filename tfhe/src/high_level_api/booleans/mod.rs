pub use base::FheBool;
pub use compact::{CompactFheBool, CompactFheBoolList};
pub use compressed::CompressedFheBool;

mod base;
mod compact;
mod compressed;
#[cfg(test)]
mod tests;
