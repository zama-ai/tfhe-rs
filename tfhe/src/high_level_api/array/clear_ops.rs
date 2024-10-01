use crate::array::cpu::ClearContainer;
use crate::array::{ClearArray, DynDimensions};
use crate::high_level_api::array::traits::{
    ArrayBackend, BackendDataContainer, ClearArithmeticArrayBackend, ClearBitwiseArrayBackend,
    HasClear,
};
use crate::high_level_api::array::FheArrayBase;
use crate::FheId;
use std::ops::{Add, BitAnd};

macro_rules! impl_other_binary_ops_variants {
    (
        $trait_name:ident($trait_method:ident) => $backend_trait:ident($backend_method:ident)
    ) => {
        impl<'a, C, Clear, Id> $trait_name<ClearArray<Clear>> for FheArrayBase<C, Id>
        where
            Id: FheId,
            Clear: Copy,
            FheArrayBase<C, Id>: HasClear<Clear = Clear>,
            C: BackendDataContainer,
            C::Backend: $backend_trait<Clear>,
        {
            type Output = FheArrayBase<<C::Backend as ArrayBackend>::Owned, Id>;

            fn $trait_method(self, rhs: ClearArray<Clear>) -> Self::Output {
                if !self.has_same_shape(&rhs) {
                    panic!("Array operands do not have the same shape");
                }
                let lhs_slice = self.as_tensor_slice();
                let rhs_slice = rhs.as_tensor_slice().map(ClearContainer::into_inner);
                let inner = C::Backend::$backend_method(lhs_slice, rhs_slice);
                let resulting_shape = DynDimensions::from(self.shape().to_vec());
                FheArrayBase::new(inner, resulting_shape)
            }
        }

        impl<'a, C, Clear, Id> $trait_name<ClearArray<Clear>> for &'a FheArrayBase<C, Id>
        where
            Id: FheId,
            Clear: Copy,

            FheArrayBase<C, Id>: HasClear<Clear = Clear>,
            C: BackendDataContainer,
            C::Backend: $backend_trait<Clear>,
        {
            type Output = FheArrayBase<<C::Backend as ArrayBackend>::Owned, Id>;

            fn $trait_method(self, rhs: ClearArray<Clear>) -> Self::Output {
                if !self.has_same_shape(&rhs) {
                    panic!("Array operands do not have the same shape");
                }
                let lhs_slice = self.as_tensor_slice();
                let rhs_slice = rhs.as_tensor_slice().map(ClearContainer::into_inner);
                let inner = C::Backend::$backend_method(lhs_slice, rhs_slice);
                let resulting_shape = DynDimensions::from(self.shape().to_vec());
                FheArrayBase::new(inner, resulting_shape)
            }
        }

        impl<'a, C, Clear, Id> $trait_name<&'a ClearArray<Clear>> for FheArrayBase<C, Id>
        where
            Id: FheId,
            Clear: Copy,

            FheArrayBase<C, Id>: HasClear<Clear = Clear>,
            C: BackendDataContainer,
            C::Backend: $backend_trait<Clear>,
        {
            type Output = FheArrayBase<<C::Backend as ArrayBackend>::Owned, Id>;

            fn $trait_method(self, rhs: &'a ClearArray<Clear>) -> Self::Output {
                if !self.has_same_shape(rhs) {
                    panic!("Array operands do not have the same shape");
                }
                let lhs_slice = self.as_tensor_slice();
                let rhs_slice = rhs.as_tensor_slice().map(ClearContainer::into_inner);
                let inner = C::Backend::$backend_method(lhs_slice, rhs_slice);
                let resulting_shape = DynDimensions::from(self.shape().to_vec());
                FheArrayBase::new(inner, resulting_shape)
            }
        }

        impl<'a, 'b, C, Clear, Id> $trait_name<&'a ClearArray<Clear>> for &'b FheArrayBase<C, Id>
        where
            Id: FheId,
            Clear: Copy,

            FheArrayBase<C, Id>: HasClear<Clear = Clear>,
            C: BackendDataContainer,
            C::Backend: $backend_trait<Clear>,
        {
            type Output = FheArrayBase<<C::Backend as ArrayBackend>::Owned, Id>;

            fn $trait_method(self, rhs: &'a ClearArray<Clear>) -> Self::Output {
                if !self.has_same_shape(rhs) {
                    panic!("Array operands do not have the same shape");
                }
                let lhs_slice = self.as_tensor_slice();
                let rhs_slice = rhs.as_tensor_slice().map(ClearContainer::into_inner);
                let inner = C::Backend::$backend_method(lhs_slice, rhs_slice);
                let resulting_shape = DynDimensions::from(self.shape().to_vec());
                FheArrayBase::new(inner, resulting_shape)
            }
        }
    };
}

impl_other_binary_ops_variants!(Add(add) => ClearArithmeticArrayBackend(add_slices));
impl_other_binary_ops_variants!(BitAnd(bitand) => ClearBitwiseArrayBackend(bitand_slice));
