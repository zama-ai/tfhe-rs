use crate::core_crypto::commons::math::tensor::Tensor;

use super::{AsMutSlice, AsRefSlice};

/// A trait for [`Tensor`]-based types, allowing to borrow the enclosed tensor.
///
/// This trait is used by the types that build on the `Tensor` type to implement multi-dimensional
/// collections of various kind. In essence, this trait allows to extract a tensor properly
/// qualified to use all the methods of the `Tensor` type:
/// ```rust
/// use tfhe::core_crypto::commons::math::tensor::{
///     AsRefSlice, AsRefTensor, Tensor,
/// };
///
/// pub struct Matrix<Cont> {
///     tensor: Tensor<Cont>,
///     row_length: usize,
/// }
///
/// pub struct Row<Cont> {
///     tensor: Tensor<Cont>,
/// }
///
/// impl<Cont> AsRefTensor for Matrix<Cont>
/// where
///     Cont: AsRefSlice,
/// {
///     type Element = Cont::Element;
///     type Container = Cont;
///     fn as_tensor(&self) -> &Tensor<Cont> {
///         &self.tensor
///     }
/// }
///
/// impl<Cont> Matrix<Cont> {
///     // Returns an iterator over the matrix rows.
///     pub fn row_iter(&self) -> impl Iterator<Item = Row<&[<Self as AsRefTensor>::Element]>>
///     where
///         Self: AsRefTensor,
///     {
///         self.as_tensor() // `AsRefTensor` method returning a `&Tensor<Cont>`
///             .as_slice() // Since `Cont` is `AsView`, so is `Tensor<Cont>`
///             .chunks(self.row_length) // Split in chunks of the size of the rows.
///             .map(|sub| Row {
///                 tensor: Tensor::from_container(sub),
///             }) // Wraps into a row type.
///     }
/// }
/// ```
pub trait AsRefTensor {
    /// The element type.
    type Element;
    /// The container used by the tensor.
    type Container: AsRefSlice<Element = <Self as AsRefTensor>::Element>;
    /// Returns a reference to the enclosed tensor.
    fn as_tensor(&self) -> &Tensor<Self::Container>;
}

/// A trait for [`Tensor`]-based types, allowing to mutably borrow the enclosed tensor.
///
/// This trait implements the same logic as `AsRefTensor`, but for mutable borrow instead. See the
/// [`AsRefTensor`] documentation for more explanations on the logic.
pub trait AsMutTensor: AsRefTensor<Element = <Self as AsMutTensor>::Element> {
    /// The element type.
    type Element;
    /// The container used by the tensor.
    type Container: AsMutSlice<Element = <Self as AsMutTensor>::Element>;
    /// Returns a mutable reference to the enclosed tensor.
    fn as_mut_tensor(&mut self) -> &mut Tensor<<Self as AsMutTensor>::Container>;
}
