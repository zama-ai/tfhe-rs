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
        size % self.group_size == 0
            && size >= self.min_inclusive_group_count * self.group_size
            && size <= self.max_inclusive_group_count * self.group_size
    }
}
