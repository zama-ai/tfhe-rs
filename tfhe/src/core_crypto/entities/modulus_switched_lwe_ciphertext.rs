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

impl<Scalar> From<StandardModulusSwitchedLweCiphertext<Scalar>> for LweCiphertext<Vec<Scalar>>
where
    Scalar: UnsignedInteger,
{
    fn from(value: StandardModulusSwitchedLweCiphertext<Scalar>) -> Self {
        Self::from_container(
            value
                .container
                .into_iter()
                // The coefficients are converted to use the power of two encoding
                .map(|coeff| coeff << (Scalar::BITS - value.log_modulus.0))
                .collect(),
            CiphertextModulus::new(1 << value.log_modulus.0),
        )
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

impl<Scalar, SwitchedScalar, C>
    From<LazyStandardModulusSwitchedLweCiphertext<Scalar, SwitchedScalar, C>>
    for LweCiphertext<Vec<SwitchedScalar>>
where
    Scalar: UnsignedInteger + CastInto<SwitchedScalar>,
    SwitchedScalar: UnsignedInteger,
    C: Container<Element = Scalar>,
{
    fn from(value: LazyStandardModulusSwitchedLweCiphertext<Scalar, SwitchedScalar, C>) -> Self {
        let cont = value
            .mask()
            .chain(std::iter::once(value.body()))
            // The coefficients are converted to use the power of two encoding
            .map(|coeff| coeff << (SwitchedScalar::BITS - value.log_modulus.0))
            .collect();

        Self::from_container(cont, CiphertextModulus::new(1 << value.log_modulus.0))
    }
}

#[cfg(test)]
mod test {
    use rand::Rng;
    use tfhe_csprng::generators::DefaultRandomGenerator;
    use tfhe_csprng::seeders::Seed;

    use crate::core_crypto::commons::generators::DeterministicSeeder;
    use crate::core_crypto::prelude::*;

    #[test]
    fn test_modswitched_to_lwe() {
        let root_seed = rand::rng().gen();
        println!("test_modswitched_to_lwe seed: 0x{root_seed:x}");

        let seed = Seed(root_seed);

        let mut seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(seed);

        let mut encryption_generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), &mut seeder);
        let mut secret_generator =
            SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

        let lwe_dimension = LweDimension(742);
        let ciphertext_modulus = CiphertextModulus::new_native();
        let lwe_noise_distribution =
            Gaussian::from_dispersion_parameter(StandardDev(0.000007069849454709433), 0.0);
        let ms_modulus_log = CiphertextModulusLog(4096u64.ilog2() as usize);
        let cleartext_modulus_log = 4;
        let cleartext_modulus = 1 << cleartext_modulus_log;
        let decoding_base_log = DecompositionBaseLog(64 - ms_modulus_log.0 + cleartext_modulus_log);

        let key =
            allocate_and_generate_new_binary_lwe_secret_key(lwe_dimension, &mut secret_generator);

        for msg in 0..cleartext_modulus {
            let plaintext = Plaintext(msg << (64 - cleartext_modulus_log));

            let input = allocate_and_encrypt_new_lwe_ciphertext(
                &key,
                plaintext,
                lwe_noise_distribution,
                ciphertext_modulus,
                &mut encryption_generator,
            );

            // Test From<LazyStandardModulusSwitchedLweCiphertext> for LweCiphertext
            let modswitched: LazyStandardModulusSwitchedLweCiphertext<u64, u64, Vec<u64>> =
                lwe_ciphertext_modulus_switch(input, ms_modulus_log);

            let lwe_ms: LweCiphertext<Vec<_>> = modswitched.clone().into();

            let decrypted_plaintext = decrypt_lwe_ciphertext(&key, &lwe_ms);

            let decomposer = SignedDecomposer::new(decoding_base_log, DecompositionLevelCount(1));

            let cleartext = decomposer.decode_plaintext(decrypted_plaintext).0 % cleartext_modulus;

            assert_eq!(cleartext, msg);

            // Test From<StandardModulusSwitchedLweCiphertext> for LweCiphertext
            let compressed_modswitched = modswitched.compress::<u64>();
            let extracted = compressed_modswitched.extract();

            let lwe_ms: LweCiphertext<Vec<_>> = extracted.into();

            let decrypted_plaintext = decrypt_lwe_ciphertext(&key, &lwe_ms);

            let decomposer = SignedDecomposer::new(decoding_base_log, DecompositionLevelCount(1));

            let cleartext = decomposer.decode_plaintext(decrypted_plaintext).0 % cleartext_modulus;

            assert_eq!(cleartext, msg);
        }
    }
}
