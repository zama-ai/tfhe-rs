//! An accelerated backend using `Concrete-FFT`.

mod implementation;
#[cfg_attr(not(feature = "__private_docs"), doc(hidden))]
pub mod private;
pub use implementation::{engines, entities};
