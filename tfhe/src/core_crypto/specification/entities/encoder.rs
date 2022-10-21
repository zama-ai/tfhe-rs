use crate::core_crypto::specification::entities::markers::EncoderKind;
use crate::core_crypto::specification::entities::AbstractEntity;

/// A trait implemented by types embodying an encoder entity.
///
/// # Formal Definition
pub trait EncoderEntity: AbstractEntity<Kind = EncoderKind> {}
