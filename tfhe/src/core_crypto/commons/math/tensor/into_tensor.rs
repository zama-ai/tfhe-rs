use crate::core_crypto::commons::math::tensor::Tensor;

use super::AsRefSlice;

/// This trait allows to extract the tensor of a [`Tensor`]-based type.
///
/// This trait allows to consume a value, and extracts the tensor that was wrapped inside, to
/// return it to the caller.
pub trait IntoTensor {
    /// The element type of the collection container.
    type Element;
    /// The type of the collection container.
    type Container: AsRefSlice<Element = <Self as IntoTensor>::Element>;
    /// Consumes `self` and returns an owned tensor.
    fn into_tensor(self) -> Tensor<Self::Container>;
}
