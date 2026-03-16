//! Module containing primitives pertaining to [`CommonMask LWE ciphertext`](`CmLweCiphertext`) linear algebra,
//! like addition, multiplication, etc.

use crate::core_crypto::algorithms::slice_algorithms::*;
use crate::core_crypto::commons::ciphertext_modulus::CiphertextModulusKind;
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::experimental::prelude::CmLweCiphertext;

pub fn cm_lwe_ciphertext_add_assign<Scalar, LhsCont, RhsCont>(
    lhs: &mut CmLweCiphertext<LhsCont>,
    rhs: &CmLweCiphertext<RhsCont>,
) where
    Scalar: UnsignedInteger,
    LhsCont: ContainerMut<Element = Scalar>,
    RhsCont: Container<Element = Scalar>,
{
    let ciphertext_modulus = rhs.ciphertext_modulus();
    if ciphertext_modulus.is_compatible_with_native_modulus() {
        cm_lwe_ciphertext_add_assign_native_mod_compatible(lhs, rhs);
    } else {
        cm_lwe_ciphertext_add_assign_other_mod(lhs, rhs);
    }
}

pub fn cm_lwe_ciphertext_add_assign_native_mod_compatible<Scalar, LhsCont, RhsCont>(
    lhs: &mut CmLweCiphertext<LhsCont>,
    rhs: &CmLweCiphertext<RhsCont>,
) where
    Scalar: UnsignedInteger,
    LhsCont: ContainerMut<Element = Scalar>,
    RhsCont: Container<Element = Scalar>,
{
    assert_eq!(
        lhs.ciphertext_modulus(),
        rhs.ciphertext_modulus(),
        "Mismatched moduli between lhs ({:?}) and rhs ({:?}) LweCiphertext",
        lhs.ciphertext_modulus(),
        rhs.ciphertext_modulus()
    );
    let ciphertext_modulus = rhs.ciphertext_modulus();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    slice_wrapping_add_assign(lhs.as_mut(), rhs.as_ref());
}

pub fn cm_lwe_ciphertext_add_assign_other_mod<Scalar, LhsCont, RhsCont>(
    lhs: &mut CmLweCiphertext<LhsCont>,
    rhs: &CmLweCiphertext<RhsCont>,
) where
    Scalar: UnsignedInteger,
    LhsCont: ContainerMut<Element = Scalar>,
    RhsCont: Container<Element = Scalar>,
{
    assert_eq!(
        lhs.ciphertext_modulus(),
        rhs.ciphertext_modulus(),
        "Mismatched moduli between lhs ({:?}) and rhs ({:?}) LweCiphertext",
        lhs.ciphertext_modulus(),
        rhs.ciphertext_modulus()
    );
    let ciphertext_modulus = rhs.ciphertext_modulus();
    assert!(!ciphertext_modulus.is_compatible_with_native_modulus());

    slice_wrapping_add_assign_custom_mod(
        lhs.as_mut(),
        rhs.as_ref(),
        ciphertext_modulus.get_custom_modulus().cast_into(),
    );
}

pub fn cm_lwe_ciphertext_add<Scalar, OutputCont, LhsCont, RhsCont>(
    output: &mut CmLweCiphertext<OutputCont>,
    lhs: &CmLweCiphertext<LhsCont>,
    rhs: &CmLweCiphertext<RhsCont>,
) where
    Scalar: UnsignedInteger,
    OutputCont: ContainerMut<Element = Scalar>,
    LhsCont: Container<Element = Scalar>,
    RhsCont: Container<Element = Scalar>,
{
    assert_eq!(
        lhs.ciphertext_modulus(),
        rhs.ciphertext_modulus(),
        "Mismatched moduli between lhs ({:?}) and rhs ({:?}) LweCiphertext",
        lhs.ciphertext_modulus(),
        rhs.ciphertext_modulus()
    );

    assert_eq!(
        output.ciphertext_modulus(),
        rhs.ciphertext_modulus(),
        "Mismatched moduli between output ({:?}) and rhs ({:?}) LweCiphertext",
        output.ciphertext_modulus(),
        rhs.ciphertext_modulus()
    );

    slice_wrapping_add(output.as_mut(), lhs.as_ref(), rhs.as_ref());
}

pub fn cm_lwe_ciphertext_plaintext_add_assign<Scalar, InCont>(
    lhs: &mut CmLweCiphertext<InCont>,
    rhs: Plaintext<Scalar>,
) where
    Scalar: UnsignedInteger,
    InCont: ContainerMut<Element = Scalar>,
{
    let ciphertext_modulus = lhs.ciphertext_modulus();
    if ciphertext_modulus.is_compatible_with_native_modulus() {
        cm_lwe_ciphertext_plaintext_add_assign_native_mod_compatible(lhs, rhs);
    } else {
        cm_lwe_ciphertext_plaintext_add_assign_other_mod(lhs, rhs);
    }
}

pub fn cm_lwe_ciphertext_plaintext_add_assign_native_mod_compatible<Scalar, InCont>(
    lhs: &mut CmLweCiphertext<InCont>,
    rhs: Plaintext<Scalar>,
) where
    Scalar: UnsignedInteger,
    InCont: ContainerMut<Element = Scalar>,
{
    let mut bodies = lhs.get_mut_bodies();
    let ciphertext_modulus = bodies.ciphertext_modulus();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    let plaintext = match ciphertext_modulus.kind() {
        CiphertextModulusKind::Native => rhs.0,
        // Manage power of 2 encoding
        CiphertextModulusKind::NonNativePowerOfTwo => rhs
            .0
            .wrapping_mul(ciphertext_modulus.get_power_of_two_scaling_to_native_torus()),
        CiphertextModulusKind::Other => unreachable!(),
    };

    for body in bodies.as_mut() {
        *body = body.wrapping_add(plaintext);
    }
}

pub fn cm_lwe_ciphertext_plaintext_add_assign_other_mod<Scalar, InCont>(
    lhs: &mut CmLweCiphertext<InCont>,
    rhs: Plaintext<Scalar>,
) where
    Scalar: UnsignedInteger,
    InCont: ContainerMut<Element = Scalar>,
{
    let mut bodies = lhs.get_mut_bodies();
    let ciphertext_modulus = bodies.ciphertext_modulus();
    assert!(!ciphertext_modulus.is_compatible_with_native_modulus());

    for body in bodies.as_mut() {
        *body = body
            .wrapping_add_custom_mod(rhs.0, ciphertext_modulus.get_custom_modulus().cast_into());
    }
}

pub fn cm_lwe_ciphertext_plaintext_sub_assign<Scalar, InCont>(
    lhs: &mut CmLweCiphertext<InCont>,
    rhs: Plaintext<Scalar>,
) where
    Scalar: UnsignedInteger,
    InCont: ContainerMut<Element = Scalar>,
{
    let ciphertext_modulus = lhs.ciphertext_modulus();
    if ciphertext_modulus.is_compatible_with_native_modulus() {
        cm_lwe_ciphertext_plaintext_sub_assign_native_mod_compatible(lhs, rhs);
    } else {
        cm_lwe_ciphertext_plaintext_sub_assign_other_mod(lhs, rhs);
    }
}

pub fn cm_lwe_ciphertext_plaintext_sub_assign_native_mod_compatible<Scalar, InCont>(
    lhs: &mut CmLweCiphertext<InCont>,
    rhs: Plaintext<Scalar>,
) where
    Scalar: UnsignedInteger,
    InCont: ContainerMut<Element = Scalar>,
{
    let mut bodies = lhs.get_mut_bodies();
    let ciphertext_modulus = bodies.ciphertext_modulus();
    assert!(ciphertext_modulus.is_compatible_with_native_modulus());

    let plaintext = match ciphertext_modulus.kind() {
        CiphertextModulusKind::Native => rhs.0,
        // Manage power of 2 encoding
        CiphertextModulusKind::NonNativePowerOfTwo => rhs
            .0
            .wrapping_mul(ciphertext_modulus.get_power_of_two_scaling_to_native_torus()),
        CiphertextModulusKind::Other => unreachable!(),
    };

    for body in bodies.as_mut() {
        *body = body.wrapping_sub(plaintext);
    }
}

pub fn cm_lwe_ciphertext_plaintext_sub_assign_other_mod<Scalar, InCont>(
    lhs: &mut CmLweCiphertext<InCont>,
    rhs: Plaintext<Scalar>,
) where
    Scalar: UnsignedInteger,
    InCont: ContainerMut<Element = Scalar>,
{
    let mut bodies = lhs.get_mut_bodies();
    let ciphertext_modulus = bodies.ciphertext_modulus();
    assert!(!ciphertext_modulus.is_compatible_with_native_modulus());

    for body in bodies.as_mut() {
        *body = body
            .wrapping_sub_custom_mod(rhs.0, ciphertext_modulus.get_custom_modulus().cast_into());
    }
}

pub fn cm_lwe_ciphertext_opposite_assign<Scalar, InCont>(ct: &mut CmLweCiphertext<InCont>)
where
    Scalar: UnsignedInteger,
    InCont: ContainerMut<Element = Scalar>,
{
    slice_wrapping_opposite_assign(ct.as_mut());
}

pub fn cm_lwe_ciphertext_cleartext_mul_assign<Scalar, InCont>(
    lhs: &mut CmLweCiphertext<InCont>,
    rhs: Cleartext<Scalar>,
) where
    Scalar: UnsignedInteger,
    InCont: ContainerMut<Element = Scalar>,
{
    slice_wrapping_scalar_mul_assign(lhs.as_mut(), rhs.0);
}

pub fn cm_lwe_ciphertext_cleartext_mul<Scalar, InputCont, OutputCont>(
    output: &mut CmLweCiphertext<OutputCont>,
    lhs: &CmLweCiphertext<InputCont>,
    rhs: Cleartext<Scalar>,
) where
    Scalar: UnsignedInteger,
    InputCont: Container<Element = Scalar>,
    OutputCont: ContainerMut<Element = Scalar>,
{
    assert_eq!(
        output.ciphertext_modulus(),
        lhs.ciphertext_modulus(),
        "Mismatched moduli between output ({:?}) and lhs ({:?}) LweCiphertext",
        output.ciphertext_modulus(),
        lhs.ciphertext_modulus()
    );
    output.as_mut().copy_from_slice(lhs.as_ref());
    cm_lwe_ciphertext_cleartext_mul_assign(output, rhs);
}

pub fn cm_lwe_ciphertext_sub_assign<Scalar, LhsCont, RhsCont>(
    lhs: &mut CmLweCiphertext<LhsCont>,
    rhs: &CmLweCiphertext<RhsCont>,
) where
    Scalar: UnsignedInteger,
    LhsCont: ContainerMut<Element = Scalar>,
    RhsCont: Container<Element = Scalar>,
{
    assert_eq!(
        lhs.ciphertext_modulus(),
        rhs.ciphertext_modulus(),
        "Mismatched moduli between lhs ({:?}) and rhs ({:?}) LweCiphertext",
        lhs.ciphertext_modulus(),
        rhs.ciphertext_modulus()
    );

    slice_wrapping_sub_assign(lhs.as_mut(), rhs.as_ref());
}

pub fn cm_lwe_ciphertext_sub<Scalar, OutputCont, LhsCont, RhsCont>(
    output: &mut CmLweCiphertext<OutputCont>,
    lhs: &CmLweCiphertext<LhsCont>,
    rhs: &CmLweCiphertext<RhsCont>,
) where
    Scalar: UnsignedInteger,
    OutputCont: ContainerMut<Element = Scalar>,
    LhsCont: Container<Element = Scalar>,
    RhsCont: Container<Element = Scalar>,
{
    assert_eq!(
        lhs.ciphertext_modulus(),
        rhs.ciphertext_modulus(),
        "Mismatched moduli between lhs ({:?}) and rhs ({:?}) LweCiphertext",
        lhs.ciphertext_modulus(),
        rhs.ciphertext_modulus()
    );

    assert_eq!(
        output.ciphertext_modulus(),
        rhs.ciphertext_modulus(),
        "Mismatched moduli between output ({:?}) and rhs ({:?}) LweCiphertext",
        output.ciphertext_modulus(),
        rhs.ciphertext_modulus()
    );

    output.as_mut().copy_from_slice(lhs.as_ref());
    cm_lwe_ciphertext_sub_assign(output, rhs);
}
