use crate::core_crypto::fft_impl::common::modulus_switch;
use crate::core_crypto::prelude::*;

pub trait ModulusSwitchedLweCiphertext<Scalar> {
    fn log_modulus(&self) -> CiphertextModulusLog;
    fn lwe_dimension(&self) -> LweDimension;
    fn body(&self) -> Scalar;
    fn mask(&self) -> impl Iterator<Item = Scalar> + '_;
}

pub fn lwe_ciphertext_modulus_switch<Scalar, SwitchedScalar, Cont>(
    lwe_in: LweCiphertext<Cont>,
    log_modulus: CiphertextModulusLog,
) -> LazyStandardModulusSwitchedLweCiphertext<Scalar, SwitchedScalar, Cont>
where
    Scalar: UnsignedInteger + CastInto<SwitchedScalar>,
    SwitchedScalar: UnsignedInteger,
    Cont: Container<Element = Scalar>,
{
    LazyStandardModulusSwitchedLweCiphertext::from_raw_parts(lwe_in, Scalar::ZERO, log_modulus)
}

pub fn lwe_ciphertext_centered_modulus_switch<Scalar, SwitchedScalar, Cont>(
    lwe_in: LweCiphertext<Cont>,
    log_modulus: CiphertextModulusLog,
) -> LazyStandardModulusSwitchedLweCiphertext<Scalar, SwitchedScalar, Cont>
where
    Scalar: UnsignedInteger + CastInto<SwitchedScalar>,
    SwitchedScalar: UnsignedInteger,
    Cont: Container<Element = Scalar>,
{
    assert!(log_modulus.0 <= Scalar::BITS);
    assert!(log_modulus.0 <= SwitchedScalar::BITS);

    let round = |a: Scalar| modulus_switch(a, log_modulus) >> (Scalar::BITS - log_modulus.0);

    let mut sum_mask_round_errors = Scalar::ZERO;

    for mask_elem in lwe_in.get_mask().as_ref().iter().copied() {
        let error = round(mask_elem).wrapping_sub(mask_elem);

        let signed_error = error.into_signed();

        let half_error = signed_error / Scalar::Signed::TWO;

        sum_mask_round_errors = sum_mask_round_errors.wrapping_add(half_error.into_unsigned());
    }

    let half_case = Scalar::ONE << (Scalar::BITS - log_modulus.0 - 1);

    let body_correction_to_add = sum_mask_round_errors.wrapping_sub(half_case);

    LazyStandardModulusSwitchedLweCiphertext::from_raw_parts(
        lwe_in,
        body_correction_to_add,
        log_modulus,
    )
}
