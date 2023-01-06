//! Module containing primitives pertaining to [`LWE ciphertext`](`LweCiphertext`) linear algebra,
//! like addition, multiplication, etc.

use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::commons::numeric::UnsignedInteger;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;

pub fn lwe_ciphertext_add_assign<Scalar, LhsCont, RhsCont>(
    lhs: &mut LweCiphertext<LhsCont>,
    rhs: &LweCiphertext<RhsCont>,
) where
    Scalar: UnsignedInteger,
    LhsCont: ContainerMut<Element = Scalar>,
    RhsCont: Container<Element = Scalar>,
{
    slice_wrapping_add_assign(lhs.as_mut(), rhs.as_ref());
}

pub fn lwe_ciphertext_add<Scalar, OutputCont, LhsCont, RhsCont>(
    output: &mut LweCiphertext<OutputCont>,
    lhs: &LweCiphertext<LhsCont>,
    rhs: &LweCiphertext<RhsCont>,
) where
    Scalar: UnsignedInteger,
    OutputCont: ContainerMut<Element = Scalar>,
    LhsCont: Container<Element = Scalar>,
    RhsCont: Container<Element = Scalar>,
{
    slice_wrapping_add(output.as_mut(), lhs.as_ref(), rhs.as_ref());
}

pub fn lwe_ciphertext_plaintext_add_assign<Scalar, InCont>(
    lhs: &mut LweCiphertext<InCont>,
    rhs: Plaintext<Scalar>,
) where
    Scalar: UnsignedInteger,
    InCont: ContainerMut<Element = Scalar>,
{
    let body = lhs.get_mut_body();

    *body.0 = (*body.0).wrapping_add(rhs.0);
}

pub fn lwe_ciphertext_opposite_assign<Scalar, InCont>(ct: &mut LweCiphertext<InCont>)
where
    Scalar: UnsignedInteger,
    InCont: ContainerMut<Element = Scalar>,
{
    slice_wrapping_opposite_assign(ct.as_mut());
}

pub fn lwe_ciphertext_cleartext_mul_assign<Scalar, InCont>(
    lhs: &mut LweCiphertext<InCont>,
    rhs: Cleartext<Scalar>,
) where
    Scalar: UnsignedInteger,
    InCont: ContainerMut<Element = Scalar>,
{
    slice_wrapping_scalar_mul_assign(lhs.as_mut(), rhs.0);
}

pub fn lwe_ciphertext_sub_assign<Scalar, LhsCont, RhsCont>(
    lhs: &mut LweCiphertext<LhsCont>,
    rhs: &LweCiphertext<RhsCont>,
) where
    Scalar: UnsignedInteger,
    LhsCont: ContainerMut<Element = Scalar>,
    RhsCont: Container<Element = Scalar>,
{
    slice_wrapping_sub_assign(lhs.as_mut(), rhs.as_ref());
}

pub fn lwe_ciphertext_cleartext_mul<Scalar, InputCont, OutputCont>(
    output: &mut LweCiphertext<OutputCont>,
    lhs: &LweCiphertext<InputCont>,
    rhs: Cleartext<Scalar>,
) where
    Scalar: UnsignedInteger,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    output.as_mut().copy_from_slice(lhs.as_ref());
    lwe_ciphertext_cleartext_mul_assign(output, rhs);
}
