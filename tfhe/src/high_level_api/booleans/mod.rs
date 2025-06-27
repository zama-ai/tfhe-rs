pub use base::{FheBool, FheBoolConformanceParams};
pub use compressed::CompressedFheBool;
pub use squashed_noise::SquashedNoiseFheBool;

pub(in crate::high_level_api) use compressed::InnerCompressedFheBool;
pub(in crate::high_level_api) use inner::{InnerBoolean, InnerBooleanVersionOwned};
pub(in crate::high_level_api) use squashed_noise::{
    InnerSquashedNoiseBoolean, InnerSquashedNoiseBooleanVersionOwned,
};

mod base;
mod compressed;
mod encrypt;
mod inner;
mod oprf;
mod squashed_noise;
#[cfg(test)]
mod tests;
