/// A trait allowing to treat a value as a reference to an alement of a different type.
pub trait AsRefElement {
    /// The element type.
    type Element;
    /// Returns a reference to the element enclosed in the type.
    fn as_element(&self) -> &Self::Element;
}

/// A trait allowing to treat a value as a mutable reference to an element of a different type.
pub trait AsMutElement: AsRefElement<Element = <Self as AsMutElement>::Element> {
    /// The element type.
    type Element;
    /// Returns a mutable reference to the element enclosed in the type.
    fn as_mut_element(&mut self) -> &mut <Self as AsMutElement>::Element;
}
