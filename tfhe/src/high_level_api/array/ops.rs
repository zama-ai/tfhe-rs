use super::stride::DynDimensions;
use super::traits::{ArithmeticArrayBackend, BitwiseArrayBackend};
use crate::high_level_api::array::{ArrayBackend, BackendDataContainer, FheArrayBase};

use std::ops::{Add, BitAnd, BitOr, BitXor, Div, Mul, Not, Rem, Sub};

macro_rules! impl_other_binary_ops_variants {
    (
        $trait_name:ident($trait_method:ident) => $backend_trait:ident($backend_method:ident)
    ) => {
        impl<'a, 'b, C1, C2, Id> $trait_name<&'a FheArrayBase<C2, Id>> for &'b FheArrayBase<C1, Id>
        where
            Id: Default,
            C1: BackendDataContainer<Backend = C2::Backend>,
            C2: BackendDataContainer,
            C1::Backend: $backend_trait,
        {
            type Output = FheArrayBase<<C1::Backend as ArrayBackend>::Owned, Id>;

            fn $trait_method(self, rhs: &'a FheArrayBase<C2, Id>) -> Self::Output {
                if !self.has_same_shape(rhs) {
                    panic!("Array operands do not have the same shape");
                }
                let result =
                    C1::Backend::$backend_method(self.as_tensor_slice(), rhs.as_tensor_slice());
                let resulting_shape = DynDimensions::from(self.shape().to_vec());
                FheArrayBase::new(result, resulting_shape)
            }
        }

        impl<'a, C1, C2, Id> $trait_name<FheArrayBase<C2, Id>> for &'a FheArrayBase<C1, Id>
        where
            Id: Default,
            C1: BackendDataContainer<Backend = C2::Backend>,
            C2: BackendDataContainer,
            C1::Backend: $backend_trait,
        {
            type Output = FheArrayBase<<C1::Backend as ArrayBackend>::Owned, Id>;

            fn $trait_method(self, rhs: FheArrayBase<C2, Id>) -> Self::Output {
                if !self.has_same_shape(&rhs) {
                    panic!("Array operands do not have the same shape");
                }
                let result =
                    C1::Backend::$backend_method(self.as_tensor_slice(), rhs.as_tensor_slice());
                let resulting_shape = DynDimensions::from(self.shape().to_vec());
                FheArrayBase::new(result, resulting_shape)
            }
        }

        impl<'a, C1, C2, Id> $trait_name<&'a FheArrayBase<C2, Id>> for FheArrayBase<C1, Id>
        where
            Id: Default,
            C1: BackendDataContainer<Backend = C2::Backend>,
            C2: BackendDataContainer,
            C1::Backend: $backend_trait,
        {
            type Output = FheArrayBase<<C1::Backend as ArrayBackend>::Owned, Id>;

            fn $trait_method(self, rhs: &'a FheArrayBase<C2, Id>) -> Self::Output {
                if !self.has_same_shape(rhs) {
                    panic!("Array operands do not have the same shape");
                }
                let result =
                    C1::Backend::$backend_method(self.as_tensor_slice(), rhs.as_tensor_slice());
                let resulting_shape = DynDimensions::from(self.shape().to_vec());
                FheArrayBase::new(result, resulting_shape)
            }
        }

        impl<C1, C2, Id> $trait_name<FheArrayBase<C2, Id>> for FheArrayBase<C1, Id>
        where
            Id: Default,
            C1: BackendDataContainer<Backend = C2::Backend>,
            C2: BackendDataContainer,
            C1::Backend: $backend_trait,
        {
            type Output = FheArrayBase<<C1::Backend as ArrayBackend>::Owned, Id>;

            fn $trait_method(self, rhs: FheArrayBase<C2, Id>) -> Self::Output {
                if !self.has_same_shape(&rhs) {
                    panic!("Array operands do not have the same shape");
                }
                let result =
                    C1::Backend::$backend_method(self.as_tensor_slice(), rhs.as_tensor_slice());
                let resulting_shape = DynDimensions::from(self.shape().to_vec());
                FheArrayBase::new(result, resulting_shape)
            }
        }
    };
}
impl_other_binary_ops_variants!(Add(add) => ArithmeticArrayBackend(add_slices));
impl_other_binary_ops_variants!(Sub(sub) => ArithmeticArrayBackend(sub_slices));
impl_other_binary_ops_variants!(Mul(mul) => ArithmeticArrayBackend(mul_slices));
impl_other_binary_ops_variants!(Div(div) => ArithmeticArrayBackend(div_slices));
impl_other_binary_ops_variants!(Rem(rem) => ArithmeticArrayBackend(rem_slices));
impl_other_binary_ops_variants!(BitAnd(bitand) => BitwiseArrayBackend(bitand));
impl_other_binary_ops_variants!(BitOr(bitor) => BitwiseArrayBackend(bitor));
impl_other_binary_ops_variants!(BitXor(bitxor) => BitwiseArrayBackend(bitxor));

impl<C1, Id, O> Not for FheArrayBase<C1, Id>
where
    C1: BackendDataContainer,
    C1::Backend: BitwiseArrayBackend,
    for<'a> &'a Self: Not<Output = O>,
{
    type Output = O;

    fn not(self) -> Self::Output {
        !(&self)
    }
}

impl<C1, Id> Not for &FheArrayBase<C1, Id>
where
    Id: Default,
    C1: BackendDataContainer,
    C1::Backend: BitwiseArrayBackend,
{
    type Output = FheArrayBase<<C1::Backend as ArrayBackend>::Owned, Id>;

    fn not(self) -> Self::Output {
        let result = C1::Backend::bitnot(self.as_tensor_slice());
        FheArrayBase::new(result, self.dims.clone())
    }
}
