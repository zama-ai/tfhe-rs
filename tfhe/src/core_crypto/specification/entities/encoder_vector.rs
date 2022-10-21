use crate::core_crypto::prelude::EncoderCount;
use crate::core_crypto::specification::entities::markers::EncoderVectorKind;
use crate::core_crypto::specification::entities::AbstractEntity;

/// A trait implemented by types embodying an encoder vector entity.
///
/// # Formal Definition
pub trait EncoderVectorEntity: AbstractEntity<Kind = EncoderVectorKind> {
    /// Returns the number of encoder contained in the vector.
    fn encoder_count(&self) -> EncoderCount;
}
