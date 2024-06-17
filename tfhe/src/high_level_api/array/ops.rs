use super::traits::{ArithmeticArrayBackend, BitwiseArrayBackend};
use crate::high_level_api::array::{
    ArrayBackend, BackendDataContainer, BackendDataContainerMut, FheArrayBase,
};
use crate::high_level_api::FheId;

use crate::IntegerId;

use std::ops::{Add, BitAnd, BitOr, BitXor, Not};

macro_rules! impl_other_binary_ops_variants {
    (
        $trait_name:ident($trait_method:ident) => $backend_trait:ident($backend_method:ident)
    ) => {
        impl<'a, 's, C1, C2, Id> $trait_name<&'a FheArrayBase<C2, Id>> for &'a FheArrayBase<C1, Id>
        where
            'a: 's,
            Id: FheId,
            C1: BackendDataContainer<Backend = C2::Backend>,
            C2: BackendDataContainer,
            C1::Backend: $backend_trait,
        {
            type Output = FheArrayBase<<C1::Backend as ArrayBackend>::Owned, Id>;

            fn $trait_method(self, rhs: &'a FheArrayBase<C2, Id>) -> Self::Output {
                let lhs = self.elems.as_slice();
                let rhs = rhs.elems.as_slice();
                let result = C1::Backend::$backend_method(lhs, rhs);
                FheArrayBase::new(result)
            }
        }

        impl<'a, C1, C2, Id> $trait_name<FheArrayBase<C2, Id>> for &'a FheArrayBase<C1, Id>
        where
            Id: FheId,
            C1: BackendDataContainer<Backend = C2::Backend>,
            C2: BackendDataContainer,
            C1::Backend: $backend_trait,
        {
            type Output = FheArrayBase<<C1::Backend as ArrayBackend>::Owned, Id>;

            fn $trait_method(self, rhs: FheArrayBase<C2, Id>) -> Self::Output {
                let lhs = self.elems.as_slice();
                let rhs = rhs.elems.as_slice();
                let result = C1::Backend::$backend_method(lhs, rhs);
                FheArrayBase::new(result)
            }
        }

        impl<'a, C1, C2, Id> $trait_name<&'a FheArrayBase<C2, Id>> for FheArrayBase<C1, Id>
        where
            Id: FheId,
            C1: BackendDataContainer<Backend = C2::Backend>,
            C2: BackendDataContainer,
            C1::Backend: $backend_trait,
        {
            type Output = FheArrayBase<<C1::Backend as ArrayBackend>::Owned, Id>;

            fn $trait_method(self, rhs: &'a FheArrayBase<C2, Id>) -> Self::Output {
                let lhs = self.elems.as_slice();
                let rhs = rhs.elems.as_slice();
                let result = C1::Backend::$backend_method(lhs, rhs);
                FheArrayBase::new(result)
            }
        }

        impl<C1, C2, Id> $trait_name<FheArrayBase<C2, Id>> for FheArrayBase<C1, Id>
        where
            Id: FheId,
            C1: BackendDataContainer<Backend = C2::Backend>,
            C2: BackendDataContainer,
            C1::Backend: $backend_trait,
        {
            type Output = FheArrayBase<<C1::Backend as ArrayBackend>::Owned, Id>;

            fn $trait_method(self, rhs: FheArrayBase<C2, Id>) -> Self::Output {
                let lhs = self.elems.as_slice();
                let rhs = rhs.elems.as_slice();
                let result = C1::Backend::$backend_method(lhs, rhs);
                FheArrayBase::new(result)
            }
        }
    };
}
impl_other_binary_ops_variants!(Add(add) => ArithmeticArrayBackend(add_slices));
impl_other_binary_ops_variants!(BitAnd(bitand) => BitwiseArrayBackend(bitand));
impl_other_binary_ops_variants!(BitOr(bitor) => BitwiseArrayBackend(bitor));
impl_other_binary_ops_variants!(BitXor(bitxor) => BitwiseArrayBackend(bitxor));

impl<C1, C2, Id> std::ops::AddAssign<FheArrayBase<C2, Id>> for FheArrayBase<C1, Id>
where
    Id: FheId,
    for<'a> Self: std::ops::AddAssign<&'a FheArrayBase<C2, Id>>,
{
    fn add_assign(&mut self, rhs: FheArrayBase<C2, Id>) {
        self.add_assign(&rhs);
    }
}

impl<'a, C1, C2, Id> std::ops::AddAssign<&'a FheArrayBase<C2, Id>> for FheArrayBase<C1, Id>
where
    Id: FheId,
    C1: BackendDataContainerMut<Backend = C2::Backend>,
    C2: BackendDataContainer,
    C1::Backend: ArithmeticArrayBackend,
{
    fn add_assign(&mut self, rhs: &'a FheArrayBase<C2, Id>) {
        let lhs = self.elems.as_slice_mut();
        let rhs = rhs.elems.as_slice();
        C1::Backend::add_assign_slices(lhs, rhs);
    }
}

impl<C1, Id, O> Not for FheArrayBase<C1, Id>
where
    Id: IntegerId,
    C1: BackendDataContainer,
    C1::Backend: BitwiseArrayBackend,
    for<'a> &'a Self: Not<Output = O>,
{
    type Output = O;

    fn not(self) -> Self::Output {
        !(&self)
    }
}

impl<'a, 's, C1, Id> Not for &'a FheArrayBase<C1, Id>
where
    'a: 's,
    Id: IntegerId,
    C1: BackendDataContainer,
    C1::Backend: BitwiseArrayBackend,
{
    type Output = FheArrayBase<<C1::Backend as ArrayBackend>::Owned, Id>;

    fn not(self) -> Self::Output {
        let lhs = self.elems.as_slice();
        let result = C1::Backend::bitnot(lhs);
        FheArrayBase::new(result)
    }
}
