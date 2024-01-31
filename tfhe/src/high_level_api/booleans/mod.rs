pub use base::FheBool;
pub use compact::{CompactFheBool, CompactFheBoolList};
pub use compressed::CompressedFheBool;

mod base;
mod compact;
mod compressed;
mod encrypt;
mod inner;
#[cfg(test)]
mod tests;
