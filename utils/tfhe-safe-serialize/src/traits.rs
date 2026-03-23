use std::marker::PhantomData;

pub trait Named {
    /// Default name for the type
    const NAME: &'static str;
    /// Aliases that should also be accepted for backward compatibility when checking the name of
    /// values of this type
    const BACKWARD_COMPATIBILITY_ALIASES: &'static [&'static str] = &[];
}

/// A trait for objects which can be checked to be conformant with a parameter set
pub trait ParameterSetConformant {
    type ParameterSet;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool;
}

/// A set of C-style enum values. This can be seen as a lightweight HashSet that derives Copy.
///
/// This can be used in conformance to let applications chose to accept previous config values
/// during a transition period and then remove support for outdated values later.
///
/// # Warning
/// As this is backed by a u128, it only supports enum of up to 128 elements
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct EnumSet<T> {
    mask: u128,
    _phantom: PhantomData<T>,
}

impl<T> Default for EnumSet<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> EnumSet<T> {
    pub const fn new() -> Self {
        Self {
            mask: 0,
            _phantom: PhantomData,
        }
    }
}

impl<T> EnumSet<T>
where
    T: Into<usize> + Copy,
{
    /// Checks if a given value is present in the set.
    pub fn contains(&self, value: T) -> bool
    where
        T: std::fmt::Debug,
    {
        let index = value.into();

        if index < 128 {
            (self.mask & (1 << index)) != 0
        } else {
            false
        }
    }

    /// Adds a value to the set.
    ///
    /// # Panic
    /// Panics if the usize representation of `value` is >= 128
    pub fn insert(&mut self, value: T) {
        let index = value.into();

        assert!(index < 128, "Config index too large for u128");

        self.mask |= 1 << index;
    }

    /// Removes a value from the set.
    pub fn remove(&mut self, value: T) {
        let index = value.into();

        if index < 128 {
            self.mask &= !(1 << index);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq)]
    enum Color {
        Red = 0,
        Green = 1,
        Blue = 2,
    }

    impl From<Color> for usize {
        fn from(c: Color) -> Self {
            c as Self
        }
    }

    #[test]
    fn insert_and_contains() {
        let mut set = EnumSet::new();
        assert!(!set.contains(Color::Red));

        set.insert(Color::Red);
        set.insert(Color::Blue);

        assert!(set.contains(Color::Red));
        assert!(!set.contains(Color::Green));
        assert!(set.contains(Color::Blue));
    }

    #[test]
    fn remove() {
        let mut set = EnumSet::new();
        set.insert(Color::Red);
        set.insert(Color::Green);

        set.remove(Color::Red);

        assert!(!set.contains(Color::Red));
        assert!(set.contains(Color::Green));
    }

    #[test]
    fn contains_out_of_range_returns_false() {
        #[derive(Debug, Clone, Copy)]
        struct Big;

        impl From<Big> for usize {
            fn from(_: Big) -> Self {
                200 // 128 is the max
            }
        }

        let set = EnumSet::new();
        assert!(!set.contains(Big));
    }
}
