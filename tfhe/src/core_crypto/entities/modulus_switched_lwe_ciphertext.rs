use std::marker::PhantomData;

use super::LweCiphertext;
use crate::core_crypto::fft_impl::common::modulus_switch;
use crate::core_crypto::prelude::packed_integers::PackedIntegers;
use crate::core_crypto::prelude::*;

/// A modulus-switched LWE ciphertext
///
/// This can be used as an input to the blind rotation.
#[derive(Clone)]
pub struct StandardModulusSwitchedLweCiphertext<Scalar> {
    container: Vec<Scalar>,
    log_modulus: CiphertextModulusLog,
}

impl<Scalar: UnsignedInteger> StandardModulusSwitchedLweCiphertext<Scalar> {
    #[cfg(test)]
    pub(crate) fn container(&self) -> &[Scalar] {
        &self.container
    }

    pub(crate) fn from_packed<PackingScalar>(
        packed_integers: &PackedIntegers<PackingScalar>,
    ) -> Self
    where
        PackingScalar: UnsignedInteger + CastInto<Scalar>,
        Scalar: UnsignedInteger,
    {
        let log_modulus = packed_integers.log_modulus();

        assert!(log_modulus.0 <= Scalar::BITS);

        let container = packed_integers.unpack::<Scalar>().collect();

        Self {
            container,
            log_modulus,
        }
    }
}

impl<Scalar: Copy> ModulusSwitchedLweCiphertext<Scalar>
    for StandardModulusSwitchedLweCiphertext<Scalar>
{
    fn log_modulus(&self) -> CiphertextModulusLog {
        self.log_modulus
    }

    fn lwe_dimension(&self) -> LweDimension {
        LweSize(self.container.len()).to_lwe_dimension()
    }

    fn body(&self) -> Scalar {
        *self.container.last().unwrap()
    }

    fn mask(&self) -> impl ExactSizeIterator<Item = Scalar> + '_ {
        let (_body, mask) = self.container.split_last().unwrap();

        mask.iter().copied()
    }
}

/// An LWE ciphertext that undergoes a modulus switch when the body and mask elements are read
///
/// This can be used as an input for the blind rotation.
#[derive(Clone, PartialEq, Eq)]
pub struct LazyStandardModulusSwitchedLweCiphertext<Scalar, SwitchedScalar, C>
where
    Scalar: UnsignedInteger + CastInto<SwitchedScalar>,
    SwitchedScalar: UnsignedInteger,
    C: Container<Element = Scalar>,
{
    lwe_in: LweCiphertext<C>,
    body_correction_to_add_before_switching: Scalar,
    log_modulus: CiphertextModulusLog,
    // Used to pin SwitchedScalar so that
    // it implements ModulusSwitchedCt<SwitchedScalar> only for SwitchedScalar
    // which helps type inference
    phantom: PhantomData<SwitchedScalar>,
}

impl<Scalar, SwitchedScalar, C> LazyStandardModulusSwitchedLweCiphertext<Scalar, SwitchedScalar, C>
where
    Scalar: UnsignedInteger + CastInto<SwitchedScalar>,
    SwitchedScalar: UnsignedInteger,
    C: Container<Element = Scalar>,
{
    pub fn into_raw_parts(self) -> (LweCiphertext<C>, Scalar, CiphertextModulusLog) {
        (
            self.lwe_in,
            self.body_correction_to_add_before_switching,
            self.log_modulus,
        )
    }

    #[track_caller]
    pub fn from_raw_parts(
        lwe_in: LweCiphertext<C>,
        body_correction_to_add_before_switching: Scalar,
        log_modulus: CiphertextModulusLog,
    ) -> Self {
        assert!(log_modulus.0 <= Scalar::BITS);
        assert!(log_modulus.0 <= SwitchedScalar::BITS);

        Self {
            lwe_in,
            body_correction_to_add_before_switching,
            log_modulus,
            phantom: PhantomData,
        }
    }

    pub fn as_view(
        &self,
    ) -> LazyStandardModulusSwitchedLweCiphertext<Scalar, SwitchedScalar, &[Scalar]> {
        LazyStandardModulusSwitchedLweCiphertext {
            lwe_in: self.lwe_in.as_view(),
            body_correction_to_add_before_switching: self.body_correction_to_add_before_switching,
            log_modulus: self.log_modulus,
            phantom: PhantomData,
        }
    }
}

impl<Scalar, SwitchedScalar, C> ModulusSwitchedLweCiphertext<SwitchedScalar>
    for LazyStandardModulusSwitchedLweCiphertext<Scalar, SwitchedScalar, C>
where
    Scalar: UnsignedInteger + CastInto<SwitchedScalar>,
    SwitchedScalar: UnsignedInteger,
    C: Container<Element = Scalar>,
{
    fn lwe_dimension(&self) -> crate::core_crypto::prelude::LweDimension {
        self.lwe_in.lwe_size().to_lwe_dimension()
    }

    fn body(&self) -> SwitchedScalar {
        modulus_switch(
            (*self.lwe_in.get_body().data)
                .wrapping_add(self.body_correction_to_add_before_switching),
            self.log_modulus,
        )
        .cast_into()
    }

    fn mask(&self) -> impl ExactSizeIterator<Item = SwitchedScalar> {
        self.lwe_in
            .as_ref()
            .split_last()
            .unwrap()
            .1
            .iter()
            .map(|i| modulus_switch(*i, self.log_modulus).cast_into())
    }

    fn log_modulus(&self) -> CiphertextModulusLog {
        self.log_modulus
    }
}
