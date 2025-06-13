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
