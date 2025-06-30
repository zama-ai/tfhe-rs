use crate::core_crypto::commons::numeric::CastInto;

use std::marker::PhantomData;

/// A trait for objects which can be checked to be conformant with a parameter set
pub trait ParameterSetConformant {
    type ParameterSet;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool;
}

/// A constraint on a list size
/// The list must be composed of a number `n` of groups of size `group_size` which means list size
/// must be a multiple of `group_size`.
/// Moreover, `n` must be:
/// - bigger or equal to `min_inclusive_group_count`
/// - smaller of equal to `max_inclusive_group_count`
#[derive(Copy, Clone)]
pub struct ListSizeConstraint {
    min_inclusive_group_count: usize,
    max_inclusive_group_count: usize,
    group_size: usize,
}

impl ListSizeConstraint {
    pub fn exact_size(size: usize) -> Self {
        Self {
            min_inclusive_group_count: size,
            max_inclusive_group_count: size,
            group_size: 1,
        }
    }
    pub fn try_size_in_range(min_inclusive: usize, max_inclusive: usize) -> Result<Self, String> {
        if max_inclusive < min_inclusive {
            return Err("max_inclusive < min_inclusive".to_owned());
        }
        Ok(Self {
            min_inclusive_group_count: min_inclusive,
            max_inclusive_group_count: max_inclusive,
            group_size: 1,
        })
    }
    pub fn try_size_of_group_in_range(
        group_size: usize,
        min_inclusive_group_count: usize,
        max_inclusive_group_count: usize,
    ) -> Result<Self, String> {
        if max_inclusive_group_count < min_inclusive_group_count {
            return Err("max_inclusive < min_inclusive".to_owned());
        }
        Ok(Self {
            min_inclusive_group_count,
            max_inclusive_group_count,
            group_size,
        })
    }

    pub fn multiply_group_size(&self, group_size_multiplier: usize) -> Self {
        Self {
            min_inclusive_group_count: self.min_inclusive_group_count,
            max_inclusive_group_count: self.max_inclusive_group_count,
            group_size: self.group_size * group_size_multiplier,
        }
    }

    pub fn is_valid(&self, size: usize) -> bool {
        if self.group_size == 0 {
            size == 0
        } else {
            size % self.group_size == 0
                && size >= self.min_inclusive_group_count * self.group_size
                && size <= self.max_inclusive_group_count * self.group_size
        }
    }
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
    T: CastInto<usize> + Copy,
{
    /// Checks if a given value is present in the set.
    pub fn contains(&self, value: T) -> bool
    where
        T: std::fmt::Debug,
    {
        let index = value.cast_into();

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
        let index = value.cast_into();

        assert!(index < 128, "Config index too large for u128");

        self.mask |= 1 << index;
    }

    /// Removes a value from the set.
    pub fn remove(&mut self, value: T) {
        let index = value.cast_into();

        if index < 128 {
            self.mask &= !(1 << index);
        }
    }
}
