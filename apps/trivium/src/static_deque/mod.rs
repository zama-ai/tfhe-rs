#[allow(clippy::module_inception)]
mod static_deque;
pub use static_deque::StaticDeque;
mod static_byte_deque;
pub use static_byte_deque::{StaticByteDeque, StaticByteDequeInput};
