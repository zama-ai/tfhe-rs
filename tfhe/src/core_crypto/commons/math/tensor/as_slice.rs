/// A trait allowing to extract a slice from a tensor.
///
/// This trait is one of the two traits which allows to use [`Tensor`](super::Tensor) whith any data
/// container.
/// This trait basically allows to extract a slice `&[T]` out of a container, to implement
/// operations directly on the slice:
/// ```rust,ignore
/// // Implementing AsSlice for Vec<T>
/// impl<Element> AsSlice for Vec<Element> {
///     type Element = Element;
///     fn as_slice(&self) -> &[Element] {
///         self.as_slice()
///     }
/// }
/// ```
/// It is akin to the [`std::borrow::Borrow`] trait from the standard library, but it is local to
/// this crate (which makes this little explanation possible), and the scalar type is an associated
/// type. Having an associated type instead of a generic type, tends to make signatures a little
/// leaner.
///
/// Finally, you should note that we have a blanket implementation that implements `AsView` for
/// `Tensor<Cont>` where `Cont` is itself `AsView`:
/// ```rust,ignore
/// impl<Cont> AsView for Tensor<Cont>
/// where
///     Cont: AsView,
/// {
///     type Scalar = Cont::Scalar;
///     fn as_view(&self) -> &[Self::Scalar] {
///         // implementation
///     }
/// }
/// ```
/// This is blanket implementation is used by the methods of the `Tensor` structure for instance.
pub trait AsRefSlice {
    /// The type of the elements of the collection.
    type Element;
    /// Returns a slice from the container.
    fn as_slice(&self) -> &[Self::Element];
}

impl<Element> AsRefSlice for Vec<Element> {
    type Element = Element;
    fn as_slice(&self) -> &[Element] {
        self.as_slice()
    }
}

impl<Element> AsRefSlice for aligned_vec::AVec<Element> {
    type Element = Element;
    fn as_slice(&self) -> &[Element] {
        self.as_slice()
    }
}

impl<Element> AsRefSlice for [Element; 1] {
    type Element = Element;
    fn as_slice(&self) -> &[Element] {
        &self[..]
    }
}

impl<Element> AsRefSlice for &[Element] {
    type Element = Element;
    fn as_slice(&self) -> &[Element] {
        self
    }
}

impl<Element> AsRefSlice for &mut [Element] {
    type Element = Element;
    fn as_slice(&self) -> &[Element] {
        self
    }
}

/// A trait allowing to extract a mutable slice from a tensor.
///
/// The logic is the same as for the `AsRefTensor`, but here, it allows to access mutable slices
/// instead. See the [`AsRefTensor`](super::AsRefTensor) documentation for a more detailed
/// explanation of the logic.
pub trait AsMutSlice: AsRefSlice<Element = <Self as AsMutSlice>::Element> {
    /// The type of the elements of the collection
    type Element;
    /// Returns a mutable slice from the container.
    fn as_mut_slice(&mut self) -> &mut [<Self as AsMutSlice>::Element];
}

impl<Element> AsMutSlice for Vec<Element> {
    type Element = Element;
    fn as_mut_slice(&mut self) -> &mut [Element] {
        self.as_mut_slice()
    }
}

impl<Element> AsMutSlice for aligned_vec::AVec<Element> {
    type Element = Element;
    fn as_mut_slice(&mut self) -> &mut [Element] {
        self.as_mut_slice()
    }
}

impl<Element> AsMutSlice for [Element; 1] {
    type Element = Element;
    fn as_mut_slice(&mut self) -> &mut [Element] {
        &mut self[..]
    }
}

impl<Element> AsMutSlice for &mut [Element] {
    type Element = Element;
    fn as_mut_slice(&mut self) -> &mut [Element] {
        self
    }
}
