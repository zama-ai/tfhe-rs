use crate::high_level_api::array::traits::{
    ArrayBackend, BackendDataContainer, ClearBitwiseArrayBackend, HasClear,
};
use crate::high_level_api::array::FheArrayBase;
use crate::FheId;
use std::ops::BitAnd;

impl<'a, C, Id> BitAnd<&'a [<Self as HasClear>::Clear]> for FheArrayBase<C, Id>
where
    Id: FheId,
    Self: HasClear,
    C: BackendDataContainer,
    C::Backend: ClearBitwiseArrayBackend<<Self as HasClear>::Clear>,
{
    type Output = FheArrayBase<<C::Backend as ArrayBackend>::Owned, Id>;

    fn bitand(self, rhs: &'a [<Self as HasClear>::Clear]) -> Self::Output {
        let lhs_slice = self.elems.as_slice();
        let inner = C::Backend::bitand_slice(lhs_slice, rhs);
        FheArrayBase::new(inner)
    }
}

impl<'a, 'b, C, Id> BitAnd<&'a [<FheArrayBase<C, Id> as HasClear>::Clear]>
    for &'b FheArrayBase<C, Id>
where
    Id: FheId,
    FheArrayBase<C, Id>: HasClear,
    C: BackendDataContainer,
    C::Backend: ClearBitwiseArrayBackend<<FheArrayBase<C, Id> as HasClear>::Clear>,
{
    type Output = FheArrayBase<<C::Backend as ArrayBackend>::Owned, Id>;

    fn bitand(self, rhs: &'a [<FheArrayBase<C, Id> as HasClear>::Clear]) -> Self::Output {
        let lhs_slice = self.elems.as_slice();
        let inner = C::Backend::bitand_slice(lhs_slice, rhs);
        FheArrayBase::new(inner)
    }
}
