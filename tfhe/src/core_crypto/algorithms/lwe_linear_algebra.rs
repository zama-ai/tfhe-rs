//! Module containing functions related to LWE ciphertext linear algebra, like addition,
//! multiplication, etc.

use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

pub fn lwe_ciphertext_in_place_addition<Scalar, LhsCont, RhsCont>(
    lhs: &mut LweCiphertextBase<LhsCont>,
    rhs: &LweCiphertextBase<RhsCont>,
) where
    Scalar: UnsignedInteger,
    LhsCont: ContainerMut<Element = Scalar>,
    RhsCont: Container<Element = Scalar>,
{
    update_with_wrapping_add(lhs.as_mut(), rhs.as_ref());
}

pub fn lwe_ciphertext_in_place_encoded_addition<Scalar, InCont>(
    lhs: &mut LweCiphertextBase<InCont>,
    rhs: Plaintext<Scalar>,
) where
    Scalar: UnsignedInteger,
    InCont: ContainerMut<Element = Scalar>,
{
    let body = lhs.get_mut_body();

    *body.0 = (*body.0).wrapping_add(rhs.0);
}

pub fn lwe_ciphertext_in_place_opposite<Scalar, InCont>(ct: &mut LweCiphertextBase<InCont>)
where
    Scalar: UnsignedInteger,
    InCont: ContainerMut<Element = Scalar>,
{
    update_with_wrapping_opposite(ct.as_mut());
}

pub fn lwe_ciphertext_in_place_cleartext_multiplication<Scalar, InCont>(
    lhs: &mut LweCiphertextBase<InCont>,
    rhs: Cleartext<Scalar>,
) where
    Scalar: UnsignedInteger,
    InCont: ContainerMut<Element = Scalar>,
{
    update_with_scalar_wrapping_mul(lhs.as_mut(), rhs.0);
}

pub fn lwe_ciphertext_in_place_subtraction<Scalar, LhsCont, RhsCont>(
    lhs: &mut LweCiphertextBase<LhsCont>,
    rhs: &LweCiphertextBase<RhsCont>,
) where
    Scalar: UnsignedInteger,
    LhsCont: ContainerMut<Element = Scalar>,
    RhsCont: Container<Element = Scalar>,
{
    update_with_wrapping_sub(lhs.as_mut(), rhs.as_ref());
}
