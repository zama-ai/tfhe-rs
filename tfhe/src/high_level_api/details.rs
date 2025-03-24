use std::ops::Deref;

/// 'smart-pointer' that holds either a borrowed T, or an owned T.
///
/// This is essentially like a Cow, except T does not need to be ToOwned
pub enum MaybeCloned<'a, T> {
    Borrowed(&'a T),
    Cloned(T),
}

impl<T> MaybeCloned<'_, T> {
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
