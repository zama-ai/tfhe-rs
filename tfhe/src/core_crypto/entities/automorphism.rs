use super::{GlweCiphertext, GlweSecretKey, Polynomial};
use crate::core_crypto::commons::utils::izip;
use crate::core_crypto::prelude::{
    CastFrom, Container, ContainerMut, ContiguousEntityContainer, ContiguousEntityContainerMut,
    PolynomialSize, UnsignedInteger,
};

pub struct Automorphism {
    power: usize,
    monomial_reducer: MonomialReducer,
}

pub struct MonomialReducer {
    modular_mask: u64,
    log_poly_size_minus_1: u64,
    modular_sign_change_mask: u64,
}

impl MonomialReducer {
    pub fn new(polynomial_size: PolynomialSize) -> Self {
        let modular_mask = (polynomial_size.0 - 1) as u64;

        let log_poly_size_minus_1 = (polynomial_size.log2().0 - 1) as u64;

        let modular_sign_change_mask = polynomial_size.0 as u64;

        Self {
            modular_mask,
            log_poly_size_minus_1,
            modular_sign_change_mask,
        }
    }

    // Modulus X^N+1
    // X^(kN+n) = X^n if k even
    // X^(kN+n) = -X^n if k odd
    // Given (kN+n) and N, this functions return n and the sign of the reduced monomial
    pub fn reduce_monomial(&self, power: u64) -> ReducedMonomial {
        // = 0 if power does not change sign
        // = 2 if power does change sign
        let should_be_negated =
            (power & self.modular_sign_change_mask) >> self.log_poly_size_minus_1;

        // = 1 if power does not change sign
        // = -1 if power does change sign
        let sign = 1.wrapping_sub(should_be_negated);

        let reduced_power = power & self.modular_mask;

        ReducedMonomial {
            sign,
            reduced_power,
        }
    }
}

pub struct ReducedMonomial {
    pub sign: u64,
    pub reduced_power: u64,
}

impl Automorphism {
    pub fn new(power: usize, polynomial_size: PolynomialSize) -> Self {
        let monomial_reducer = MonomialReducer::new(polynomial_size);

        Self {
            power,
            monomial_reducer,
        }
    }

    /// Applies the automorphism to the input polynomial and store the result to the output
    ///
    /// ```rust
    /// use tfhe::core_crypto::entities::automorphism::Automorphism;
    /// use tfhe::core_crypto::prelude::{
    ///     CastFrom, Container, ContainerMut, Polynomial, PolynomialSize, UnsignedInteger,
    /// };
    ///
    /// let polynomial_size = PolynomialSize(8);
    ///
    /// let in_polynomial = Polynomial::from_container(vec![0_u64, 1, 2, 3, 4, 5, 6, 7]);
    /// let mut out_polynomial = Polynomial::from_container(vec![0_u64; 8]);
    ///
    /// let automorphism = Automorphism::new(3, polynomial_size);
    ///
    /// automorphism.apply_to_polynomial(&in_polynomial, &mut out_polynomial);
    ///
    /// let expected_result = [
    ///     0,
    ///     3.wrapping_neg(),
    ///     6,
    ///     1,
    ///     4.wrapping_neg(),
    ///     7,
    ///     2,
    ///     5.wrapping_neg(),
    /// ];
    /// assert_eq!(out_polynomial.as_ref(), expected_result.as_slice());
    /// ```
    pub fn apply_to_polynomial<Scalar, InCont, OutCont>(
        &self,
        input: &Polynomial<InCont>,
        output: &mut Polynomial<OutCont>,
    ) where
        Scalar: UnsignedInteger + CastFrom<usize>,
        InCont: Container<Element = Scalar>,
        OutCont: ContainerMut<Element = Scalar>,
    {
        let output = output.as_mut();

        let mut power = 0;

        for in_polynomial_coeff in input.as_ref().iter() {
            let ReducedMonomial {
                sign,
                reduced_power,
            } = self.monomial_reducer.reduce_monomial(power);

            output[reduced_power as usize] =
                Scalar::cast_from(sign as usize).wrapping_mul(*in_polynomial_coeff);

            power += self.power as u64;
        }
    }

    /// Applies the automorphism to the input polynomial and store the result to the output
    ///
    /// ```rust
    /// use tfhe::core_crypto::entities::automorphism::Automorphism;
    /// use tfhe::core_crypto::prelude::{
    ///     CastFrom, CiphertextModulus, Container, ContainerMut, GlweCiphertext, GlweSize, Polynomial,
    ///     PolynomialSize, UnsignedInteger,
    /// };
    ///
    /// let polynomial_size = PolynomialSize(8);
    /// let glwe_size = GlweSize(2);
    /// let ciphertetx_modulus = CiphertextModulus::new_native();
    ///
    /// let in_glwe = GlweCiphertext::from_container(
    ///     vec![0_u64, 1, 2, 3, 4, 5, 6, 7, 0_u64, 1, 2, 3, 4, 5, 6, 7],
    ///     polynomial_size,
    ///     ciphertetx_modulus,
    /// );
    /// let mut out_glwe =
    ///     GlweCiphertext::from_container(vec![0_u64; 16], polynomial_size, ciphertetx_modulus);
    ///
    /// let automorphism = Automorphism::new(3, polynomial_size);
    ///
    /// automorphism.apply_to_glwe_ciphertext(&in_glwe, &mut out_glwe);
    ///
    /// let expected_result = [
    ///     0,
    ///     3.wrapping_neg(),
    ///     6,
    ///     1,
    ///     4.wrapping_neg(),
    ///     7,
    ///     2,
    ///     5.wrapping_neg(),
    ///     0,
    ///     3.wrapping_neg(),
    ///     6,
    ///     1,
    ///     4.wrapping_neg(),
    ///     7,
    ///     2,
    ///     5.wrapping_neg(),
    /// ];
    /// assert_eq!(out_glwe.as_ref(), expected_result.as_slice());
    /// ```
    pub fn apply_to_glwe_ciphertext<Scalar, InCont, OutCont>(
        &self,
        input: &GlweCiphertext<InCont>,
        output: &mut GlweCiphertext<OutCont>,
    ) where
        Scalar: UnsignedInteger + CastFrom<usize>,
        InCont: Container<Element = Scalar>,
        OutCont: ContainerMut<Element = Scalar>,
    {
        for (i, mut j) in izip!(input.iter(), output.iter_mut()) {
            self.apply_to_polynomial(&i, &mut j);
        }
    }

    pub fn apply_to_glwe_secret_key<Scalar, InCont, OutCont>(
        &self,
        input: &GlweSecretKey<InCont>,
        output: &mut GlweSecretKey<OutCont>,
    ) where
        Scalar: UnsignedInteger + CastFrom<usize>,
        InCont: Container<Element = Scalar>,
        OutCont: ContainerMut<Element = Scalar>,
    {
        for (i, mut j) in izip!(
            input.as_polynomial_list().iter(),
            output.as_polynomial_list_mut().iter_mut()
        ) {
            self.apply_to_polynomial(&i, &mut j);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::core_crypto::commons::utils::izip;
    use crate::core_crypto::entities::automorphism::Automorphism;
    use crate::core_crypto::prelude::*;

    #[test]
    fn glwe_automorphism_then_ks_to_initial_key() {
        let log_polynomial_size = 3;

        let polynomial_size = PolynomialSize(1 << log_polynomial_size);
        let glwe_size = GlweSize(2);
        let ciphertext_modulus = CiphertextModulus::new_native();

        let decomp_base_log = DecompositionBaseLog(8);
        let decomp_level_count = DecompositionLevelCount(3);
        let glwe_noise_distribution = Gaussian::from_dispersion_parameter(
            StandardDev(0.00000000000000029403601535432533),
            0.0,
        );

        // Create the PRNG
        let mut seeder = new_seeder();
        let seeder = seeder.as_mut();
        let mut encryption_generator =
            EncryptionRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed(), seeder);
        let mut secret_generator =
            SecretRandomGenerator::<DefaultRandomGenerator>::new(seeder.seed());

        // Create the GlweSecretKey
        let glwe_secret_key = allocate_and_generate_new_binary_glwe_secret_key(
            glwe_size.to_glwe_dimension(),
            polynomial_size,
            &mut secret_generator,
        );

        let plaintext_input = (0..polynomial_size.0 as u64)
            .map(|a| a << (64 - log_polynomial_size))
            .collect::<Vec<u64>>();

        let plaintext_list = PlaintextList::from_container(plaintext_input.clone());

        let mut in_glwe = GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);

        encrypt_glwe_ciphertext(
            &glwe_secret_key,
            &mut in_glwe,
            &plaintext_list,
            glwe_noise_distribution,
            &mut encryption_generator,
        );

        let mut after_autom_glwe =
            GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);

        let automorphism = Automorphism::new(3, polynomial_size);

        let mut autom_glwe_secret_key =
            GlweSecretKey::new_empty_key(0, glwe_size.to_glwe_dimension(), polynomial_size);

        automorphism.apply_to_glwe_secret_key(&glwe_secret_key, &mut autom_glwe_secret_key);

        automorphism.apply_to_glwe_ciphertext(&in_glwe, &mut after_autom_glwe);

        let decrypt_compare_glwe =
            |glwe_secret_key, encrypted_glwe, expected_polynomial: Polynomial<Vec<u64>>| {
                let mut out_plaintext_list =
                    PlaintextList::new(0, PlaintextCount(polynomial_size.0));

                decrypt_glwe_ciphertext(glwe_secret_key, encrypted_glwe, &mut out_plaintext_list);

                let decomposer = SignedDecomposer::new(
                    DecompositionBaseLog(log_polynomial_size),
                    DecompositionLevelCount(1),
                );

                for (out_encoded, modified_input_encoded) in izip!(
                    out_plaintext_list.as_ref().iter(),
                    expected_polynomial.as_ref()
                ) {
                    let out_encoded = decomposer.decode_plaintext(Plaintext(*out_encoded));

                    let modified_input_decoded =
                        decomposer.decode_plaintext(Plaintext(*modified_input_encoded));

                    assert_eq!(out_encoded, modified_input_decoded);
                }
            };

        // Check autom(enc(sk, p)) = enc(autom(sk), autom(p))
        {
            let in_polynomial = Polynomial::from_container(plaintext_input.clone());

            let mut automorphism_on_input = Polynomial::from_container(vec![0; polynomial_size.0]);

            automorphism.apply_to_polynomial(&in_polynomial, &mut automorphism_on_input);

            decrypt_compare_glwe(
                &autom_glwe_secret_key,
                &after_autom_glwe,
                automorphism_on_input,
            );
        }

        // Check ks(autom(sk)-> sk, autom(enc(sk, p))) = enc(sk, autom(p))
        {
            let ksk = allocate_and_generate_new_glwe_keyswitch_key(
                &autom_glwe_secret_key,
                &glwe_secret_key,
                decomp_base_log,
                decomp_level_count,
                glwe_noise_distribution,
                ciphertext_modulus,
                &mut encryption_generator,
            );

            let mut output_glwe =
                GlweCiphertext::new(0u64, glwe_size, polynomial_size, ciphertext_modulus);

            keyswitch_glwe_ciphertext(&ksk, &after_autom_glwe, &mut output_glwe);

            let in_polynomial = Polynomial::from_container(plaintext_input);

            let mut automorphism_on_input = Polynomial::from_container(vec![0; polynomial_size.0]);

            automorphism.apply_to_polynomial(&in_polynomial, &mut automorphism_on_input);

            decrypt_compare_glwe(&glwe_secret_key, &output_glwe, automorphism_on_input);
        }
    }
}
