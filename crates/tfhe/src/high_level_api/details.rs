use std::ops::Deref;

/// 'smart-pointer' that holds either a borrowed T, or an owned T.
pub(crate) enum MaybeCloned<'a, T> {
    Borrowed(&'a T),
    #[allow(dead_code)]
    Cloned(T),
}

impl<'a, T> MaybeCloned<'a, T> {
    pub(crate) fn into_owned(self) -> T
    where
        T: ToOwned<Owned = T>,
    {
        match self {
            Self::Borrowed(b) => b.to_owned(),
            Self::Cloned(o) => o,
        }
    }
}

impl<T> Deref for MaybeCloned<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Borrowed(b) => b,
            Self::Cloned(o) => o,
        }
    }
}
