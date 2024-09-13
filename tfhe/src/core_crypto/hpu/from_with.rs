//! Define From/Into conversion trait with extra parameters
//! Enable to convert from tfhers entities into Hpu entities

pub trait FromWith<T, P>: Sized {
    /// Converts to this T type from the input type with parameter P.
    fn from_with(value: T, param: P) -> Self;
}

pub trait IntoWith<T, P>: Sized {
    /// Converts this type into the (usually inferred) input type.
    fn into_with(self, param: P) -> T;
}

// From implies Into
impl<T, P, U> IntoWith<U, P> for T
where
    U: FromWith<T, P>,
{
    /// Calls `U::from_with(self, param)`.
    ///
    /// That is, this conversion is whatever the implementation of
    /// <code>[FromWith]&lt;T, P&gt; for U</code> chooses to do.
    #[inline]
    #[track_caller]
    fn into_with(self, param: P) -> U {
        U::from_with(self, param)
    }
}
