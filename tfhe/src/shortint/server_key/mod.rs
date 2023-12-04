//! Module with the definition of the ServerKey.
//!
//! This module implements the generation of the server public key, together with all the
//! available homomorphic integer operations.
mod add;
mod bitwise_op;
mod comp_op;
mod div_mod;
mod mul;
mod neg;
mod scalar_add;
mod scalar_bitwise_op;
mod scalar_mul;
mod scalar_sub;
mod shift;
mod sub;

pub mod compressed;
pub use compressed::{CompressedServerKey, ShortintCompressedBootstrappingKey};

#[cfg(test)]
mod tests;

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweSize, LweDimension, PolynomialSize,
    ThreadCount,
};
use crate::core_crypto::commons::traits::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::fft_impl::fft64::crypto::bootstrap::FourierLweBootstrapKey;
use crate::core_crypto::fft_impl::fft64::math::fft::Fft;
use crate::shortint::ciphertext::{Ciphertext, Degree, MaxDegree, MaxNoiseLevel, NoiseLevel};
use crate::shortint::client_key::ClientKey;
use crate::shortint::engine::{fill_accumulator, ShortintEngine};
use crate::shortint::parameters::{
    CarryModulus, CiphertextConformanceParams, CiphertextModulus, MessageModulus,
};
use crate::shortint::server_key::add::unchecked_add_assign;
use crate::shortint::PBSOrder;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};

/// Error returned when the carry buffer is full.
#[derive(Debug)]
pub enum CheckError {
    CarryFull {
        degree: Degree,
        max_degree: MaxDegree,
    },
    NoiseTooBig {
        noise_level: NoiseLevel,
        max_noise_level: MaxNoiseLevel,
    },
}

impl Display for CheckError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CarryFull { degree, max_degree } => {
                write!(
                    f,
                    "The degree (={}) should not exceed {}",
                    degree.get(),
                    max_degree.get(),
                )
            }
            Self::NoiseTooBig {
                noise_level,
                max_noise_level,
            } => {
                write!(
                    f,
                    "The noise (={}) should not exceed {}",
                    noise_level.get(),
                    max_noise_level.get(),
                )
            }
        }
    }
}

impl std::error::Error for CheckError {}

#[derive(Clone, Debug, PartialEq)]
pub enum ShortintBootstrappingKey {
    Classic(FourierLweBootstrapKeyOwned),
    MultiBit {
        fourier_bsk: FourierLweMultiBitBootstrapKeyOwned,
        thread_count: ThreadCount,
        deterministic_execution: bool,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(bound(deserialize = "C: IntoContainerOwned"))]
enum SerializableShortintBootstrappingKey<C: Container<Element = concrete_fft::c64>> {
    Classic(FourierLweBootstrapKey<C>),
    MultiBit {
        fourier_bsk: FourierLweMultiBitBootstrapKey<C>,
        deterministic_execution: bool,
    },
}

impl Serialize for ShortintBootstrappingKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Classic(bsk) => SerializableShortintBootstrappingKey::Classic(bsk.as_view()),
            Self::MultiBit {
                fourier_bsk: bsk,
                deterministic_execution,
                ..
            } => SerializableShortintBootstrappingKey::MultiBit {
                fourier_bsk: bsk.as_view(),
                deterministic_execution: *deterministic_execution,
            },
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ShortintBootstrappingKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let deser_sk = SerializableShortintBootstrappingKey::deserialize(deserializer)?;

        match deser_sk {
            SerializableShortintBootstrappingKey::Classic(bsk) => Ok(Self::Classic(bsk)),
            SerializableShortintBootstrappingKey::MultiBit {
                fourier_bsk,
                deterministic_execution,
            } => {
                let thread_count = ShortintEngine::with_thread_local_mut(|engine| {
                    engine.get_thread_count_for_multi_bit_pbs(
                        fourier_bsk.input_lwe_dimension(),
                        fourier_bsk.glwe_size().to_glwe_dimension(),
                        fourier_bsk.polynomial_size(),
                        fourier_bsk.decomposition_base_log(),
                        fourier_bsk.decomposition_level_count(),
                        fourier_bsk.grouping_factor(),
                    )
                });
                Ok(Self::MultiBit {
                    fourier_bsk,
                    thread_count,
                    deterministic_execution,
                })
            }
        }
    }
}

impl ShortintBootstrappingKey {
    pub fn input_lwe_dimension(&self) -> LweDimension {
        match self {
            Self::Classic(inner) => inner.input_lwe_dimension(),
            Self::MultiBit {
                fourier_bsk: inner, ..
            } => inner.input_lwe_dimension(),
        }
    }

    pub fn polynomial_size(&self) -> PolynomialSize {
        match self {
            Self::Classic(inner) => inner.polynomial_size(),
            Self::MultiBit {
                fourier_bsk: inner, ..
            } => inner.polynomial_size(),
        }
    }

    pub fn glwe_size(&self) -> GlweSize {
        match self {
            Self::Classic(inner) => inner.glwe_size(),
            Self::MultiBit {
                fourier_bsk: inner, ..
            } => inner.glwe_size(),
        }
    }

    pub fn decomposition_base_log(&self) -> DecompositionBaseLog {
        match self {
            Self::Classic(inner) => inner.decomposition_base_log(),
            Self::MultiBit {
                fourier_bsk: inner, ..
            } => inner.decomposition_base_log(),
        }
    }

    pub fn decomposition_level_count(&self) -> DecompositionLevelCount {
        match self {
            Self::Classic(inner) => inner.decomposition_level_count(),
            Self::MultiBit {
                fourier_bsk: inner, ..
            } => inner.decomposition_level_count(),
        }
    }

    pub fn output_lwe_dimension(&self) -> LweDimension {
        match self {
            Self::Classic(inner) => inner.output_lwe_dimension(),
            Self::MultiBit {
                fourier_bsk: inner, ..
            } => inner.output_lwe_dimension(),
        }
    }

    pub fn bootstrapping_key_size_elements(&self) -> usize {
        match self {
            Self::Classic(bsk) => bsk.as_view().data().len(),
            Self::MultiBit {
                fourier_bsk: bsk, ..
            } => bsk.as_view().data().len(),
        }
    }

    pub fn bootstrapping_key_size_bytes(&self) -> usize {
        match self {
            Self::Classic(bsk) => std::mem::size_of_val(bsk.as_view().data()),
            Self::MultiBit {
                fourier_bsk: bsk, ..
            } => std::mem::size_of_val(bsk.as_view().data()),
        }
    }

    /// Indicate whether the PBS algorithm is deterministic, i.e. will produce the same bit-exact
    /// output when run twice on the same bit-exact input.
    ///
    /// Note: the classic PBS algorithm is always deterministic.
    pub fn deterministic_pbs_execution(&self) -> bool {
        match self {
            Self::Classic(_) => true,
            Self::MultiBit {
                deterministic_execution,
                ..
            } => *deterministic_execution,
        }
    }

    /// Set the choice of PBS algorithm to have the `new_deterministic_execution` behavior.
    ///
    /// Note: the classic PBS algorithm is always deterministic and calling this function on a
    /// [`ServerKey`] made from [`super::ClassicPBSParameters`] is a no-op.
    pub fn set_deterministic_pbs_execution(&mut self, new_deterministic_execution: bool) {
        match self {
            // Classic PBS is already deterministic no matter what
            Self::Classic(_) => (),
            Self::MultiBit {
                deterministic_execution,
                ..
            } => *deterministic_execution = new_deterministic_execution,
        }
    }
}

/// A structure containing the server public key.
///
/// The server key is generated by the client and is meant to be published: the client
/// sends it to the server so it can compute homomorphic circuits.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServerKey {
    pub key_switching_key: LweKeyswitchKeyOwned<u64>,
    pub bootstrapping_key: ShortintBootstrappingKey,
    // Size of the message buffer
    pub message_modulus: MessageModulus,
    // Size of the carry buffer
    pub carry_modulus: CarryModulus,
    // Maximum number of operations that can be done before emptying the operation buffer
    pub max_degree: MaxDegree,
    pub max_noise_level: MaxNoiseLevel,
    // Modulus use for computations on the ciphertext
    pub ciphertext_modulus: CiphertextModulus,
    pub pbs_order: PBSOrder,
}

impl ServerKey {
    pub fn conformance_params(&self) -> CiphertextConformanceParams {
        let lwe_dim = match self.pbs_order {
            PBSOrder::KeyswitchBootstrap => self.key_switching_key.input_key_lwe_dimension(),
            PBSOrder::BootstrapKeyswitch => self.key_switching_key.output_key_lwe_dimension(),
        };

        let ct_params = LweCiphertextParameters {
            lwe_dim,
            ct_modulus: self.ciphertext_modulus,
        };

        CiphertextConformanceParams {
            ct_params,
            message_modulus: self.message_modulus,
            carry_modulus: self.carry_modulus,
            degree: Degree::new(self.message_modulus.0 - 1),
            pbs_order: self.pbs_order,
            noise_level: NoiseLevel::NOMINAL,
        }
    }
}

/// Returns whether it is possible to pack lhs and rhs into a unique
/// ciphertext without exceeding the max storable value using the formula:
/// `unique_ciphertext = (lhs * factor) + rhs`
fn ciphertexts_can_be_packed_without_exceeding_space_or_noise(
    server_key: &ServerKey,
    lhs: &Ciphertext,
    rhs: &Ciphertext,
    factor: usize,
) -> Result<(), CheckError> {
    let final_degree = (lhs.degree * factor) + rhs.degree;

    let max_degree = MaxDegree::from_msg_carry_modulus(lhs.message_modulus, lhs.carry_modulus);

    max_degree.validate(final_degree)?;

    server_key
        .max_noise_level
        .validate(lhs.noise_level() * factor + rhs.noise_level())?;

    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct LookupTable<C: Container<Element = u64>> {
    pub acc: GlweCiphertext<C>,
    pub degree: Degree,
}

pub type LookupTableOwned = LookupTable<Vec<u64>>;
pub type LookupTableMutView<'a> = LookupTable<&'a mut [u64]>;
pub type LookupTableView<'a> = LookupTable<&'a [u64]>;

#[must_use]
pub struct BivariateLookupTable<C: Container<Element = u64>> {
    // A bivariate lookup table is an univariate loolookup table
    // where the message space is shared to encode
    // 2 values
    pub acc: LookupTable<C>,
    // By how much we shift the lhs in the LUT
    pub ct_right_modulus: MessageModulus,
}

pub type BivariateLookupTableOwned = BivariateLookupTable<Vec<u64>>;
pub type BivariateLookupTableMutView<'a> = BivariateLookupTable<&'a mut [u64]>;
pub type BivariateLookupTableView<'a> = BivariateLookupTable<&'a [u64]>;

impl<C: Container<Element = u64>> BivariateLookupTable<C> {
    pub fn is_bivariate_pbs_possible(
        &self,
        server_key: &ServerKey,
        lhs: &Ciphertext,
        rhs: &Ciphertext,
    ) -> Result<(), CheckError> {
        ciphertexts_can_be_packed_without_exceeding_space_or_noise(
            server_key,
            lhs,
            rhs,
            self.ct_right_modulus.0,
        )?;
        Ok(())
    }
}

impl ServerKey {
    /// Generate a server key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// use tfhe::shortint::{gen_keys, ServerKey};
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// // Generate the server key:
    /// let sks = ServerKey::new(&cks);
    /// ```
    pub fn new(cks: &ClientKey) -> Self {
        ShortintEngine::with_thread_local_mut(|engine| engine.new_server_key(cks))
    }

    /// Generate a server key with a chosen maximum degree
    pub fn new_with_max_degree(cks: &ClientKey, max_degree: MaxDegree) -> Self {
        ShortintEngine::with_thread_local_mut(|engine| {
            engine.new_server_key_with_max_degree(cks, max_degree)
        })
    }

    /// Constructs the lookup table given a function as input.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 3;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// // Generate the lookup table for the function f: x -> x*x mod 4
    /// let f = |x: u64| x.pow(2) % 4;
    /// let acc = sks.generate_lookup_table(f);
    /// let ct_res = sks.apply_lookup_table(&ct, &acc);
    ///
    /// let dec = cks.decrypt(&ct_res);
    /// // 3**2 mod 4 = 1
    /// assert_eq!(dec, f(msg));
    /// ```
    pub fn generate_lookup_table<F>(&self, f: F) -> LookupTableOwned
    where
        F: Fn(u64) -> u64,
    {
        let mut acc = GlweCiphertext::new(
            0,
            self.bootstrapping_key.glwe_size(),
            self.bootstrapping_key.polynomial_size(),
            self.ciphertext_modulus,
        );
        let max_value = fill_accumulator(&mut acc, self, f);

        LookupTableOwned {
            acc,
            degree: Degree::new(max_value as usize),
        }
    }

    /// Given a function as input, constructs the lookup table working on the message bits
    /// Carry bits are ignored
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 3;
    ///
    /// let ct = cks.encrypt(msg);
    ///
    /// // Generate the lookup table on message for the function f: x -> x*x
    /// let f = |x: u64| x.pow(2);
    ///
    /// let acc = sks.generate_msg_lookup_table(f, ct.message_modulus);
    /// let ct_res = sks.apply_lookup_table(&ct, &acc);
    ///
    /// let dec = cks.decrypt(&ct_res);
    /// // 3^2 mod 4 = 1
    /// assert_eq!(dec, f(msg) % 4);
    /// ```
    pub fn generate_msg_lookup_table<F>(&self, f: F, modulus: MessageModulus) -> LookupTableOwned
    where
        F: Fn(u64) -> u64,
    {
        self.generate_lookup_table(|x| f(x % modulus.0 as u64) % modulus.0 as u64)
    }

    /// Generates a bivariate accumulator
    pub fn generate_lookup_table_bivariate_with_factor<F>(
        &self,
        f: F,
        left_message_scaling: MessageModulus,
    ) -> BivariateLookupTableOwned
    where
        F: Fn(u64, u64) -> u64,
    {
        // Depending on the factor used, rhs and / or lhs may have carries
        // (degree >= message_modulus) which is why we need to apply the message_modulus
        // to clear them
        let factor_u64 = left_message_scaling.0 as u64;
        let message_modulus = self.message_modulus.0 as u64;
        let wrapped_f = |input: u64| -> u64 {
            let lhs = (input / factor_u64) % message_modulus;
            let rhs = (input % factor_u64) % message_modulus;

            f(lhs, rhs)
        };
        let accumulator = self.generate_lookup_table(wrapped_f);

        BivariateLookupTable {
            acc: accumulator,
            ct_right_modulus: left_message_scaling,
        }
    }

    /// Constructs the lookup table for a given bivariate function as input.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg_1 = 3;
    /// let msg_2 = 2;
    ///
    /// let mut ct1 = cks.encrypt(msg_1);
    /// let mut ct2 = cks.encrypt(msg_2);
    ///
    /// let f = |x, y| (x + y) % 4;
    ///
    /// let acc = sks.generate_lookup_table_bivariate(f);
    /// acc.is_bivariate_pbs_possible(&sks, &ct1, &ct2).unwrap();
    /// let ct_res = sks.smart_apply_lookup_table_bivariate(&mut ct1, &mut ct2, &acc);
    ///
    /// let dec = cks.decrypt(&ct_res);
    /// assert_eq!(dec, f(msg_1, msg_2));
    /// ```
    pub fn generate_lookup_table_bivariate<F>(&self, f: F) -> BivariateLookupTableOwned
    where
        F: Fn(u64, u64) -> u64,
    {
        self.generate_lookup_table_bivariate_with_factor(f, self.message_modulus)
    }

    /// Compute a keyswitch and programmable bootstrap.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg: u64 = 3;
    /// let msg2: u64 = 2;
    /// let ct1 = cks.encrypt(msg);
    /// let ct2 = cks.encrypt(msg2);
    /// let modulus = cks.parameters.message_modulus().0 as u64;
    ///
    /// // Generate the lookup table for the function f: x, y -> (x * y * x) mod 4
    /// let acc = sks.generate_lookup_table_bivariate(|x, y| x * y * x % modulus);
    /// let ct_res = sks.unchecked_apply_lookup_table_bivariate(&ct1, &ct2, &acc);
    ///
    /// let dec = cks.decrypt(&ct_res);
    /// assert_eq!(dec, (msg * msg2 * msg) % modulus);
    /// ```
    pub fn unchecked_apply_lookup_table_bivariate(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
        acc: &BivariateLookupTableOwned,
    ) -> Ciphertext {
        let mut ct_res = ct_left.clone();
        self.unchecked_apply_lookup_table_bivariate_assign(&mut ct_res, ct_right, acc);
        ct_res
    }

    pub fn unchecked_apply_lookup_table_bivariate_assign(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
        acc: &BivariateLookupTableOwned,
    ) {
        let modulus = (ct_right.degree.get() + 1) as u64;
        assert!(modulus <= acc.ct_right_modulus.0 as u64);

        // Message 1 is shifted
        self.unchecked_scalar_mul_assign(ct_left, acc.ct_right_modulus.0 as u8);

        unchecked_add_assign(ct_left, ct_right);

        // Compute the PBS
        self.apply_lookup_table_assign(ct_left, &acc.acc);
    }

    /// Compute a keyswitch and programmable bootstrap.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg: u64 = 3;
    /// let msg2: u64 = 2;
    /// let mut ct1 = cks.encrypt(msg);
    /// let mut ct2 = cks.encrypt(msg2);
    /// let modulus = cks.parameters.message_modulus().0 as u64;
    ///
    /// // Generate the lookup table for the function f: x, y -> (x * y * x) mod 4
    /// let acc = sks.generate_lookup_table_bivariate(|x, y| x * y * x % modulus);
    /// let ct_res = sks.smart_apply_lookup_table_bivariate(&mut ct1, &mut ct2, &acc);
    ///
    /// let dec = cks.decrypt(&ct_res);
    /// assert_eq!(dec, (msg * msg2 * msg) % modulus);
    /// ```
    pub fn smart_apply_lookup_table_bivariate(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
        acc: &BivariateLookupTableOwned,
    ) -> Ciphertext {
        if self
            .is_functional_bivariate_pbs_possible(ct_left, ct_right)
            .is_err()
        {
            // After the message_extract, we'll have ct_left, ct_right in [0, message_modulus[
            // so the factor has to be message_modulus
            assert_eq!(ct_right.message_modulus.0, acc.ct_right_modulus.0);
            self.message_extract_assign(ct_left);
            self.message_extract_assign(ct_right);
        }

        self.is_functional_bivariate_pbs_possible(ct_left, ct_right)
            .unwrap();

        self.unchecked_apply_lookup_table_bivariate(ct_left, ct_right, acc)
    }

    pub fn smart_apply_lookup_table_bivariate_assign(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
        acc: &BivariateLookupTableOwned,
    ) {
        if self
            .is_functional_bivariate_pbs_possible(ct_left, ct_right)
            .is_err()
        {
            // After the message_extract, we'll have ct_left, ct_right in [0, message_modulus[
            // so the factor has to be message_modulus
            assert_eq!(ct_right.message_modulus.0, acc.ct_right_modulus.0);
            self.message_extract_assign(ct_left);
            self.message_extract_assign(ct_right);
        }

        self.is_functional_bivariate_pbs_possible(ct_left, ct_right)
            .unwrap();

        self.unchecked_apply_lookup_table_bivariate_assign(ct_left, ct_right, acc);
    }

    /// Compute a keyswitch and programmable bootstrap.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg: u64 = 3;
    /// let ct = cks.encrypt(msg);
    /// let modulus = cks.parameters.message_modulus().0 as u64;
    ///
    /// // Generate the lookup table for the function f: x -> x*x*x mod 4
    /// let acc = sks.generate_lookup_table(|x| x * x * x % modulus);
    /// let ct_res = sks.apply_lookup_table(&ct, &acc);
    ///
    /// let dec = cks.decrypt(&ct_res);
    /// // (3*3*3) mod 4 = 3
    /// assert_eq!(dec, (msg * msg * msg) % modulus);
    /// ```
    pub fn apply_lookup_table(&self, ct: &Ciphertext, acc: &LookupTableOwned) -> Ciphertext {
        let mut ct_res = ct.clone();

        self.apply_lookup_table_assign(&mut ct_res, acc);

        ct_res
    }

    pub fn apply_lookup_table_assign(&self, ct: &mut Ciphertext, acc: &LookupTableOwned) {
        match self.pbs_order {
            PBSOrder::KeyswitchBootstrap => {
                // This updates the ciphertext degree
                self.keyswitch_programmable_bootstrap_assign(ct, acc);
            }
            PBSOrder::BootstrapKeyswitch => {
                // This updates the ciphertext degree
                self.programmable_bootstrap_keyswitch_assign(ct, acc);
            }
        };
    }

    /// Generic programmable bootstrap where messages are concatenated into one ciphertext to
    /// evaluate a bivariate function. This is used to apply many binary operations (comparisons,
    /// multiplications, division).
    pub fn unchecked_evaluate_bivariate_function<F>(
        &self,
        ct_left: &Ciphertext,
        ct_right: &Ciphertext,
        f: F,
    ) -> Ciphertext
    where
        F: Fn(u64, u64) -> u64,
    {
        let mut ct_res = ct_left.clone();
        self.unchecked_evaluate_bivariate_function_assign(&mut ct_res, ct_right, f);
        ct_res
    }

    pub fn unchecked_evaluate_bivariate_function_assign<F>(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &Ciphertext,
        f: F,
    ) where
        F: Fn(u64, u64) -> u64,
    {
        // Generate the lookup _table for the function
        let factor = MessageModulus(ct_right.degree.get() + 1);
        let lookup_table = self.generate_lookup_table_bivariate_with_factor(f, factor);

        self.unchecked_apply_lookup_table_bivariate_assign(ct_left, ct_right, &lookup_table);
    }

    /// Verify if a functional bivariate pbs can be applied on ct_left and ct_right.
    pub fn is_functional_bivariate_pbs_possible(
        &self,
        ct1: &Ciphertext,
        ct2: &Ciphertext,
    ) -> Result<(), CheckError> {
        ciphertexts_can_be_packed_without_exceeding_space_or_noise(
            self,
            ct1,
            ct2,
            ct2.degree.get() + 1,
        )?;

        Ok(())
    }

    pub fn smart_evaluate_bivariate_function_assign<F>(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
        f: F,
    ) where
        F: Fn(u64, u64) -> u64,
    {
        if self
            .is_functional_bivariate_pbs_possible(ct_left, ct_right)
            .is_err()
        {
            // We don't have enough space in carries, so clear them
            self.message_extract_assign(ct_left);
            self.message_extract_assign(ct_right);
        }
        self.is_functional_bivariate_pbs_possible(ct_left, ct_right)
            .unwrap();

        let factor = MessageModulus(ct_right.degree.get() + 1);

        // Generate the lookup table for the function
        let lookup_table = self.generate_lookup_table_bivariate_with_factor(f, factor);

        self.unchecked_apply_lookup_table_bivariate_assign(ct_left, ct_right, &lookup_table);
    }

    pub fn smart_evaluate_bivariate_function<F>(
        &self,
        ct_left: &mut Ciphertext,
        ct_right: &mut Ciphertext,
        f: F,
    ) -> Ciphertext
    where
        F: Fn(u64, u64) -> u64,
    {
        if self
            .is_functional_bivariate_pbs_possible(ct_left, ct_right)
            .is_err()
        {
            // We don't have enough space in carries, so clear them
            self.message_extract_assign(ct_left);
            self.message_extract_assign(ct_right);
        }
        self.is_functional_bivariate_pbs_possible(ct_left, ct_right)
            .unwrap();

        let factor = MessageModulus(ct_right.degree.get() + 1);

        // Generate the lookup table for the function
        let lookup_table = self.generate_lookup_table_bivariate_with_factor(f, factor);

        self.unchecked_apply_lookup_table_bivariate(ct_left, ct_right, &lookup_table)
    }
    /// Replace the input encrypted message by the value of its carry buffer.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let clear = 9;
    ///
    /// // Encrypt a message
    /// let mut ct = cks.unchecked_encrypt(clear);
    ///
    /// // |       ct        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  1 0  |   0 1   |
    ///
    /// // Compute homomorphically carry extraction
    /// sks.carry_extract_assign(&mut ct);
    ///
    /// // |       ct        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   1 0   |
    ///
    /// // Decrypt:
    /// let res = cks.decrypt_message_and_carry(&ct);
    /// assert_eq!(2, res);
    /// ```
    pub fn carry_extract_assign(&self, ct: &mut Ciphertext) {
        let modulus = ct.message_modulus.0 as u64;

        let lookup_table = self.generate_lookup_table(|x| x / modulus);

        self.apply_lookup_table_assign(ct, &lookup_table);
    }

    /// Extract a new ciphertext encrypting the input carry buffer.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let clear = 9;
    ///
    /// // Encrypt a message
    /// let ct = cks.unchecked_encrypt(clear);
    ///
    /// // |       ct        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  1 0  |   0 1   |
    ///
    /// // Compute homomorphically carry extraction
    /// let ct_res = sks.carry_extract(&ct);
    ///
    /// // |     ct_res      |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   1 0   |
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(2, res);
    /// ```
    pub fn carry_extract(&self, ct: &Ciphertext) -> Ciphertext {
        let mut result = ct.clone();
        self.carry_extract_assign(&mut result);
        result
    }

    /// Clears the carry buffer of the input ciphertext.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let clear = 9;
    ///
    /// // Encrypt a message
    /// let mut ct = cks.unchecked_encrypt(clear);
    ///
    /// // |       ct        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  1 0  |   0 1   |
    ///
    /// // Compute homomorphically the message extraction
    /// sks.message_extract_assign(&mut ct);
    ///
    /// // |       ct        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   0 1   |
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct);
    /// assert_eq!(1, res);
    /// ```
    pub fn message_extract_assign(&self, ct: &mut Ciphertext) {
        let acc = self.generate_msg_lookup_table(|x| x, ct.message_modulus);

        self.apply_lookup_table_assign(ct, &acc);
    }

    /// Extract a new ciphertext containing only the message i.e., with a cleared carry buffer.
    ///
    /// # Example
    ///
    ///```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let clear = 9;
    ///
    /// // Encrypt a message
    /// let ct = cks.unchecked_encrypt(clear);
    ///
    /// // |       ct        |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  1 0  |   0 1   |
    ///
    /// // Compute homomorphically the message extraction
    /// let ct_res = sks.message_extract(&ct);
    ///
    /// // |     ct_res      |
    /// // | carry | message |
    /// // |-------|---------|
    /// // |  0 0  |   0 1   |
    ///
    /// // Decrypt:
    /// let res = cks.decrypt(&ct_res);
    /// assert_eq!(1, res);
    /// ```
    pub fn message_extract(&self, ct: &Ciphertext) -> Ciphertext {
        let mut result = ct.clone();
        self.message_extract_assign(&mut result);
        result
    }

    /// Compute a trivial shortint ciphertext with the dimension of the big LWE secret key from a
    /// given value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    /// use tfhe::shortint::{gen_keys, Ciphertext};
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 1;
    ///
    /// // Trivial encryption
    /// let ct1: Ciphertext = sks.create_trivial(msg);
    ///
    /// let ct_res = cks.decrypt(&ct1);
    /// assert_eq!(1, ct_res);
    /// ```
    pub fn create_trivial(&self, value: u64) -> Ciphertext {
        let modular_value = value as usize % self.message_modulus.0;
        self.unchecked_create_trivial(modular_value as u64)
    }

    pub fn unchecked_create_trivial(&self, value: u64) -> Ciphertext {
        let lwe_size = match self.pbs_order {
            PBSOrder::KeyswitchBootstrap => {
                self.bootstrapping_key.output_lwe_dimension().to_lwe_size()
            }
            PBSOrder::BootstrapKeyswitch => {
                self.bootstrapping_key.input_lwe_dimension().to_lwe_size()
            }
        };

        let delta = (1_u64 << 63) / (self.message_modulus.0 * self.carry_modulus.0) as u64;

        let shifted_value = value * delta;

        let encoded = Plaintext(shifted_value);

        let ct = allocate_and_trivially_encrypt_new_lwe_ciphertext(
            lwe_size,
            encoded,
            self.ciphertext_modulus,
        );

        let degree = Degree::new(value as usize);

        Ciphertext::new(
            ct,
            degree,
            NoiseLevel::ZERO,
            self.message_modulus,
            self.carry_modulus,
            self.pbs_order,
        )
    }

    pub fn create_trivial_assign(&self, ct: &mut Ciphertext, value: u64) {
        let modular_value = value as usize % self.message_modulus.0;

        let delta = (1_u64 << 63) / (self.message_modulus.0 * self.carry_modulus.0) as u64;

        let shifted_value = (modular_value as u64) * delta;

        let encoded = Plaintext(shifted_value);

        trivially_encrypt_lwe_ciphertext(&mut ct.ct, encoded);

        ct.degree = Degree::new(modular_value);
        ct.set_noise_level(NoiseLevel::ZERO);
    }

    pub fn bootstrapping_key_size_elements(&self) -> usize {
        self.bootstrapping_key.bootstrapping_key_size_elements()
    }

    pub fn bootstrapping_key_size_bytes(&self) -> usize {
        self.bootstrapping_key.bootstrapping_key_size_bytes()
    }

    pub fn key_switching_key_size_elements(&self) -> usize {
        self.key_switching_key.as_ref().len()
    }

    pub fn key_switching_key_size_bytes(&self) -> usize {
        std::mem::size_of_val(self.key_switching_key.as_ref())
    }

    pub fn deterministic_pbs_execution(&self) -> bool {
        self.bootstrapping_key.deterministic_pbs_execution()
    }

    pub fn set_deterministic_pbs_execution(&mut self, new_deterministic_execution: bool) {
        self.bootstrapping_key
            .set_deterministic_pbs_execution(new_deterministic_execution);
    }

    fn trivial_pbs_assign(&self, ct: &mut Ciphertext, acc: &LookupTableOwned) {
        assert_eq!(ct.noise_level(), NoiseLevel::ZERO);
        let modulus_sup = self.message_modulus.0 * self.carry_modulus.0;
        let delta = (1_u64 << 63) / (self.message_modulus.0 * self.carry_modulus.0) as u64;
        let ct_value = *ct.ct.get_body().data / delta;

        let box_size = self.bootstrapping_key.polynomial_size().0 / modulus_sup;
        let result = if ct_value >= modulus_sup as u64 {
            // padding bit is 1
            let ct_value = ct_value % modulus_sup as u64;
            let index_in_lut = ct_value as usize * box_size;
            acc.acc.get_body().as_ref()[index_in_lut].wrapping_neg()
        } else {
            let index_in_lut = ct_value as usize * box_size;
            acc.acc.get_body().as_ref()[index_in_lut]
        };
        *ct.ct.get_mut_body().data = result;
        ct.degree = acc.degree;
    }

    pub(crate) fn keyswitch_programmable_bootstrap_assign(
        &self,
        ct: &mut Ciphertext,
        acc: &LookupTableOwned,
    ) {
        if ct.is_trivial() {
            self.trivial_pbs_assign(ct, acc);
            return;
        }

        ShortintEngine::with_thread_local_mut(|engine| {
            // Compute the programmable bootstrapping with fixed test polynomial
            let (mut ciphertext_buffers, buffers) = engine.get_buffers(self);

            // Compute a key switch
            keyswitch_lwe_ciphertext(
                &self.key_switching_key,
                &ct.ct,
                &mut ciphertext_buffers.buffer_lwe_after_ks,
            );

            match &self.bootstrapping_key {
                ShortintBootstrappingKey::Classic(fourier_bsk) => {
                    let fft = Fft::new(fourier_bsk.polynomial_size());
                    let fft = fft.as_view();
                    buffers.resize(
                        programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement::<u64>(
                            fourier_bsk.glwe_size(),
                            fourier_bsk.polynomial_size(),
                            fft,
                        )
                        .unwrap()
                        .unaligned_bytes_required(),
                    );
                    let stack = buffers.stack();

                    // Compute a bootstrap
                    programmable_bootstrap_lwe_ciphertext_mem_optimized(
                        &ciphertext_buffers.buffer_lwe_after_ks,
                        &mut ct.ct,
                        &acc.acc,
                        fourier_bsk,
                        fft,
                        stack,
                    );
                }
                ShortintBootstrappingKey::MultiBit {
                    fourier_bsk,
                    thread_count,
                    deterministic_execution,
                } => {
                    if *deterministic_execution {
                        multi_bit_deterministic_programmable_bootstrap_lwe_ciphertext(
                            &ciphertext_buffers.buffer_lwe_after_ks,
                            &mut ct.ct,
                            &acc.acc,
                            fourier_bsk,
                            *thread_count,
                        );
                    } else {
                        multi_bit_programmable_bootstrap_lwe_ciphertext(
                            &ciphertext_buffers.buffer_lwe_after_ks,
                            &mut ct.ct,
                            &acc.acc,
                            fourier_bsk,
                            *thread_count,
                        );
                    }
                }
            };
        });

        ct.degree = acc.degree;
        ct.set_noise_level(NoiseLevel::NOMINAL);
    }

    pub(crate) fn programmable_bootstrap_keyswitch_assign(
        &self,
        ct: &mut Ciphertext,
        acc: &LookupTableOwned,
    ) {
        if ct.is_trivial() {
            self.trivial_pbs_assign(ct, acc);
            return;
        }

        ShortintEngine::with_thread_local_mut(|engine| {
            let (mut ciphertext_buffers, buffers) = engine.get_buffers(self);

            match &self.bootstrapping_key {
                ShortintBootstrappingKey::Classic(fourier_bsk) => {
                    let fft = Fft::new(fourier_bsk.polynomial_size());
                    let fft = fft.as_view();
                    buffers.resize(
                        programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement::<u64>(
                            fourier_bsk.glwe_size(),
                            fourier_bsk.polynomial_size(),
                            fft,
                        )
                        .unwrap()
                        .unaligned_bytes_required(),
                    );
                    let stack = buffers.stack();

                    // Compute a bootstrap
                    programmable_bootstrap_lwe_ciphertext_mem_optimized(
                        &ct.ct,
                        &mut ciphertext_buffers.buffer_lwe_after_pbs,
                        &acc.acc,
                        fourier_bsk,
                        fft,
                        stack,
                    );
                }
                ShortintBootstrappingKey::MultiBit {
                    fourier_bsk,
                    thread_count,
                    deterministic_execution,
                } => {
                    if *deterministic_execution {
                        multi_bit_deterministic_programmable_bootstrap_lwe_ciphertext(
                            &ct.ct,
                            &mut ciphertext_buffers.buffer_lwe_after_pbs,
                            &acc.acc,
                            fourier_bsk,
                            *thread_count,
                        );
                    } else {
                        multi_bit_programmable_bootstrap_lwe_ciphertext(
                            &ct.ct,
                            &mut ciphertext_buffers.buffer_lwe_after_pbs,
                            &acc.acc,
                            fourier_bsk,
                            *thread_count,
                        );
                    }
                }
            };

            // Compute a key switch
            keyswitch_lwe_ciphertext(
                &self.key_switching_key,
                &ciphertext_buffers.buffer_lwe_after_pbs,
                &mut ct.ct,
            );
        });

        ct.degree = acc.degree;
        ct.set_noise_level(NoiseLevel::NOMINAL);
    }
}

impl From<CompressedServerKey> for ServerKey {
    fn from(compressed_server_key: CompressedServerKey) -> Self {
        let CompressedServerKey {
            key_switching_key,
            bootstrapping_key,
            message_modulus,
            carry_modulus,
            max_degree,
            ciphertext_modulus,
            pbs_order,
        } = compressed_server_key;

        let (key_switching_key, bootstrapping_key) = rayon::join(
            || key_switching_key.par_decompress_into_lwe_keyswitch_key(),
            || match bootstrapping_key {
                ShortintCompressedBootstrappingKey::Classic(bootstrapping_key) => {
                    let standard_bootstrapping_key =
                        bootstrapping_key.par_decompress_into_lwe_bootstrap_key();

                    let mut bootstrapping_key = FourierLweBootstrapKeyOwned::new(
                        standard_bootstrapping_key.input_lwe_dimension(),
                        standard_bootstrapping_key.glwe_size(),
                        standard_bootstrapping_key.polynomial_size(),
                        standard_bootstrapping_key.decomposition_base_log(),
                        standard_bootstrapping_key.decomposition_level_count(),
                    );

                    par_convert_standard_lwe_bootstrap_key_to_fourier(
                        &standard_bootstrapping_key,
                        &mut bootstrapping_key,
                    );

                    ShortintBootstrappingKey::Classic(bootstrapping_key)
                }
                ShortintCompressedBootstrappingKey::MultiBit {
                    seeded_bsk: bootstrapping_key,
                    deterministic_execution,
                } => {
                    let standard_bootstrapping_key =
                        bootstrapping_key.par_decompress_into_lwe_multi_bit_bootstrap_key();

                    let mut bootstrapping_key = FourierLweMultiBitBootstrapKeyOwned::new(
                        standard_bootstrapping_key.input_lwe_dimension(),
                        standard_bootstrapping_key.glwe_size(),
                        standard_bootstrapping_key.polynomial_size(),
                        standard_bootstrapping_key.decomposition_base_log(),
                        standard_bootstrapping_key.decomposition_level_count(),
                        standard_bootstrapping_key.grouping_factor(),
                    );

                    par_convert_standard_lwe_multi_bit_bootstrap_key_to_fourier(
                        &standard_bootstrapping_key,
                        &mut bootstrapping_key,
                    );

                    let thread_count = ShortintEngine::with_thread_local_mut(|engine| {
                        engine.get_thread_count_for_multi_bit_pbs(
                            standard_bootstrapping_key.input_lwe_dimension(),
                            standard_bootstrapping_key.glwe_size().to_glwe_dimension(),
                            standard_bootstrapping_key.polynomial_size(),
                            standard_bootstrapping_key.decomposition_base_log(),
                            standard_bootstrapping_key.decomposition_level_count(),
                            standard_bootstrapping_key.grouping_factor(),
                        )
                    });

                    ShortintBootstrappingKey::MultiBit {
                        fourier_bsk: bootstrapping_key,
                        thread_count,
                        deterministic_execution,
                    }
                }
            },
        );

        let max_noise_level = MaxNoiseLevel::from_msg_carry_modulus(message_modulus, carry_modulus);

        Self {
            key_switching_key,
            bootstrapping_key,
            message_modulus,
            carry_modulus,
            max_degree,
            max_noise_level,
            ciphertext_modulus,
            pbs_order,
        }
    }
}
