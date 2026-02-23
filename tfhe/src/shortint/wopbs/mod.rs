//! Module with the definition of the WopbsKey (WithOut padding PBS Key).
//!
//! This module implements the generation of another server public key, which allows to compute
//! an alternative version of the programmable bootstrapping. This does not require the use of a
//! bit of padding.
//!
//! In the case where a padding bit is defined, keys are generated so that there a compatible for
//! both uses.

use crate::core_crypto::entities::*;

use crate::shortint::WopbsParameters;
use serde::{Deserialize, Serialize};

#[cfg(all(test, feature = "experimental"))]
mod test;

// Struct for WoPBS based on the private functional packing keyswitch.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(dylint_lib = "tfhe_lints", allow(serialize_without_versionize))]
pub struct WopbsKey {
    //Key for the private functional keyswitch
    pub wopbs_server_key: StandardServerKey,
    pub pbs_server_key: StandardServerKey,
    pub cbs_pfpksk: LwePrivateFunctionalPackingKeyswitchKeyListOwned<u64>,
    pub ksk_pbs_to_wopbs: LweKeyswitchKeyOwned<u64>,
    pub param: WopbsParameters,
}

#[cfg(feature = "experimental")]
pub use experimental::*;

use super::server_key::StandardServerKey;

#[cfg(feature = "experimental")]
mod experimental {
    use crate::core_crypto::algorithms::*;
    use crate::core_crypto::commons::parameters::*;
    use crate::core_crypto::commons::traits::*;
    use crate::core_crypto::entities::*;
    use crate::core_crypto::fft_impl::fft64::math::fft::Fft;
    use crate::shortint::atomic_pattern::AtomicPattern;
    use crate::shortint::ciphertext::*;
    use crate::shortint::client_key::StandardClientKeyView;
    use crate::shortint::engine::ShortintEngine;
    use crate::shortint::server_key::{
        ShortintBootstrappingKey, StandardServerKey, StandardServerKeyView,
    };

    use super::WopbsKey;
    use crate::shortint::{ServerKey, WopbsParameters};

    #[derive(Debug)]
    pub enum WopbsKeyCreationError {
        UnsupportedMultiBit,
    }

    impl std::error::Error for WopbsKeyCreationError {}

    impl std::fmt::Display for WopbsKeyCreationError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::UnsupportedMultiBit => {
                    write!(f, "WopbsKey does not yet support using multi bit PBS")
                }
            }
        }
    }

    #[must_use]
    pub struct WopbsLUTBase {
        // Flattened Wopbs LUT
        plaintext_list: Vec<u64>,
        // How many output ciphertexts will be produced after applying the Wopbs to an input vector
        // of ciphertexts encrypting bits
        output_ciphertext_count: CiphertextCount,
    }

    impl WopbsLUTBase {
        pub fn from_vec(value: Vec<u64>, output_ciphertext_count: CiphertextCount) -> Self {
            Self {
                plaintext_list: value,
                output_ciphertext_count,
            }
        }

        pub fn new(
            small_lut_size: PlaintextCount,
            output_ciphertext_count: CiphertextCount,
        ) -> Self {
            Self {
                plaintext_list: vec![0; small_lut_size.0 * output_ciphertext_count.0],
                output_ciphertext_count,
            }
        }

        pub fn lut(&self) -> PlaintextListView<'_, u64> {
            PlaintextList::from_container(&self.plaintext_list)
        }

        pub fn lut_mut(&mut self) -> PlaintextListMutView<'_, u64> {
            PlaintextList::from_container(&mut self.plaintext_list)
        }

        pub fn output_ciphertext_count(&self) -> CiphertextCount {
            self.output_ciphertext_count
        }

        pub fn small_lut_size(&self) -> PlaintextCount {
            PlaintextCount(self.lut().plaintext_count().0 / self.output_ciphertext_count().0)
        }

        pub fn get_small_lut(&self, index: usize) -> &[u64] {
            assert!(
                index < self.output_ciphertext_count().0,
                "index {index} out of bounds, max {}",
                self.output_ciphertext_count().0
            );

            let small_lut_size = self.small_lut_size().0;

            &self.plaintext_list[index * small_lut_size..(index + 1) * small_lut_size]
        }

        pub fn get_small_lut_mut(&mut self, index: usize) -> &mut [u64] {
            assert!(
                index < self.output_ciphertext_count().0,
                "index {index} out of bounds, max {}",
                self.output_ciphertext_count().0
            );

            let small_lut_size = self.small_lut_size().0;

            &mut self.plaintext_list[index * small_lut_size..(index + 1) * small_lut_size]
        }
    }

    impl AsRef<[u64]> for WopbsLUTBase {
        fn as_ref(&self) -> &[u64] {
            self.plaintext_list.as_ref()
        }
    }

    impl AsMut<[u64]> for WopbsLUTBase {
        fn as_mut(&mut self) -> &mut [u64] {
            self.plaintext_list.as_mut()
        }
    }

    #[must_use]
    pub struct ShortintWopbsLUT {
        inner: WopbsLUTBase,
    }

    impl ShortintWopbsLUT {
        pub fn new(lut_size: PlaintextCount) -> Self {
            Self {
                inner: WopbsLUTBase::new(lut_size, CiphertextCount(1)),
            }
        }

        pub fn iter(&self) -> std::slice::Iter<'_, u64> {
            self.inner.as_ref().iter()
        }

        pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, u64> {
            self.inner.as_mut().iter_mut()
        }
    }

    impl<'a> IntoIterator for &'a ShortintWopbsLUT {
        type IntoIter = std::slice::Iter<'a, u64>;
        type Item = &'a u64;
        fn into_iter(self) -> Self::IntoIter {
            self.iter()
        }
    }

    impl<'a> IntoIterator for &'a mut ShortintWopbsLUT {
        type IntoIter = std::slice::IterMut<'a, u64>;
        type Item = &'a mut u64;
        fn into_iter(self) -> Self::IntoIter {
            self.iter_mut()
        }
    }

    impl AsRef<WopbsLUTBase> for ShortintWopbsLUT {
        fn as_ref(&self) -> &WopbsLUTBase {
            &self.inner
        }
    }

    impl AsMut<WopbsLUTBase> for ShortintWopbsLUT {
        fn as_mut(&mut self) -> &mut WopbsLUTBase {
            &mut self.inner
        }
    }

    impl std::ops::Index<usize> for ShortintWopbsLUT {
        type Output = u64;

        fn index(&self, index: usize) -> &Self::Output {
            &self.inner.as_ref()[index]
        }
    }

    impl std::ops::IndexMut<usize> for ShortintWopbsLUT {
        fn index_mut(&mut self, index: usize) -> &mut Self::Output {
            &mut self.inner.as_mut()[index]
        }
    }

    impl TryFrom<Vec<Vec<u64>>> for ShortintWopbsLUT {
        type Error = &'static str;

        fn try_from(mut value: Vec<Vec<u64>>) -> Result<Self, Self::Error> {
            if value.len() != 1 {
                return Err("ShortintWopbsLUT can only contain one small lut");
            }

            let value = value.remove(0);

            Ok(Self {
                inner: WopbsLUTBase::from_vec(value, CiphertextCount(1)),
            })
        }
    }

    impl From<Vec<u64>> for ShortintWopbsLUT {
        fn from(value: Vec<u64>) -> Self {
            Self {
                inner: WopbsLUTBase::from_vec(value, CiphertextCount(1)),
            }
        }
    }

    impl WopbsKey {
        /// Generate the server key required to compute a WoPBS from the client and the server keys.
        ///
        /// #Warning
        /// Only when the classical PBS is not used in the circuit
        ///
        /// # Example
        ///
        /// ```rust
        /// use tfhe::shortint::gen_keys;
        /// use tfhe::shortint::parameters::parameters_wopbs_only::LEGACY_WOPBS_ONLY_8_BLOCKS_PARAM_MESSAGE_1_CARRY_1_KS_PBS;
        /// use tfhe::shortint::wopbs::*;
        ///
        /// // Generate the client key and the server key:
        /// let (cks, sks) = gen_keys(LEGACY_WOPBS_ONLY_8_BLOCKS_PARAM_MESSAGE_1_CARRY_1_KS_PBS);
        /// let wopbs_key = WopbsKey::new_wopbs_key_only_for_wopbs(cks.as_view().try_into().unwrap(),
        ///                                                        sks.as_view().try_into().unwrap());
        /// ```
        pub fn new_wopbs_key_only_for_wopbs(
            cks: StandardClientKeyView<'_>,
            sks: StandardServerKeyView<'_>,
        ) -> Self {
            ShortintEngine::with_thread_local_mut(|engine| {
                engine.new_wopbs_key_only_for_wopbs(cks, sks).unwrap()
            })
        }

        /// Generate the server key required to compute a WoPBS from the client and the server keys.
        /// # Example
        ///
        /// ```rust
        /// use tfhe::shortint::gen_keys;
        /// use tfhe::shortint::parameters::parameters_wopbs_message_carry::LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS;
        /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
        /// use tfhe::shortint::wopbs::*;
        ///
        /// // Generate the client key and the server key:
        /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128);
        /// let wopbs_key = WopbsKey::new_wopbs_key(cks.as_view().try_into().unwrap(), sks.as_view().try_into().unwrap(),
        ///                                         &LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        /// ```
        pub fn new_wopbs_key(
            cks: StandardClientKeyView<'_>,
            sks: StandardServerKeyView<'_>,
            parameters: &WopbsParameters,
        ) -> Self {
            ShortintEngine::with_thread_local_mut(|engine| {
                engine.new_wopbs_key(cks, sks, parameters)
            })
        }

        /// Deconstruct a [`WopbsKey`] into its constituents.
        pub fn into_raw_parts(
            self,
        ) -> (
            StandardServerKey,
            StandardServerKey,
            LwePrivateFunctionalPackingKeyswitchKeyListOwned<u64>,
            LweKeyswitchKeyOwned<u64>,
            WopbsParameters,
        ) {
            let Self {
                wopbs_server_key,
                pbs_server_key,
                cbs_pfpksk,
                ksk_pbs_to_wopbs,
                param,
            } = self;

            (
                wopbs_server_key,
                pbs_server_key,
                cbs_pfpksk,
                ksk_pbs_to_wopbs,
                param,
            )
        }

        /// Construct a [`WopbsKey`] from its constituents.
        ///
        /// # Panics
        ///
        /// Panics if the constituents are not compatible with each others.
        pub fn from_raw_parts(
            wopbs_server_key: StandardServerKey,
            pbs_server_key: StandardServerKey,
            cbs_pfpksk: LwePrivateFunctionalPackingKeyswitchKeyListOwned<u64>,
            ksk_pbs_to_wopbs: LweKeyswitchKeyOwned<u64>,
            param: WopbsParameters,
        ) -> Self {
            assert_eq!(
                ksk_pbs_to_wopbs.input_key_lwe_dimension(),
                pbs_server_key.ciphertext_lwe_dimension()
            );

            assert_eq!(
                ksk_pbs_to_wopbs.output_key_lwe_dimension(),
                wopbs_server_key.ciphertext_lwe_dimension()
            );

            // TODO add asserts/conformance checks for the wopbs key

            Self {
                wopbs_server_key,
                pbs_server_key,
                cbs_pfpksk,
                ksk_pbs_to_wopbs,
                param,
            }
        }

        /// Generate the Look-Up Table homomorphically using the WoPBS approach.
        ///
        /// # Warning: this assumes one bit of padding.
        ///
        /// # Example
        ///
        /// ```rust
        /// use tfhe::shortint::gen_keys;
        /// use tfhe::shortint::parameters::parameters_wopbs_message_carry::LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS;
        /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
        /// use tfhe::shortint::wopbs::*;
        ///
        /// // Generate the client key and the server key:
        /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128);
        /// let std_sks = sks.as_view().try_into().unwrap();
        /// let std_cks = cks.as_view().try_into().unwrap();
        /// let wopbs_key = WopbsKey::new_wopbs_key(std_cks, std_sks, &LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        /// let message_modulus = LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS.message_modulus.0;
        /// let m = 2;
        /// let ct = cks.encrypt(m);
        /// let lut = wopbs_key.generate_lut(&ct, |x| x * x % message_modulus);
        /// let ct_res = wopbs_key.programmable_bootstrapping(&sks, &ct, &lut);
        /// let res = cks.decrypt(&ct_res);
        /// assert_eq!(res, (m * m) % message_modulus);
        /// ```
        pub fn generate_lut<F>(&self, ct: &Ciphertext, f: F) -> ShortintWopbsLUT
        where
            F: Fn(u64) -> u64,
        {
            // The function is applied only on the message modulus bits
            let basis = ct.message_modulus.0 * ct.carry_modulus.0;
            let delta = 64 - f64::log2(basis as f64).ceil() as u64 - 1;
            let poly_size = self
                .wopbs_server_key
                .atomic_pattern
                .bootstrapping_key
                .polynomial_size()
                .0;
            let mut lut = ShortintWopbsLUT::new(PlaintextCount(poly_size));
            for (i, value) in lut.iter_mut().enumerate().take(basis as usize) {
                *value = f(i as u64 % ct.message_modulus.0) << delta;
            }
            lut
        }

        /// Generate the Look-Up Table homomorphically using the WoPBS approach.
        ///
        /// # Warning: this assumes no bit of padding.
        ///
        /// # Example
        ///
        /// ```rust
        /// use tfhe::shortint::gen_keys;
        /// use tfhe::shortint::parameters::parameters_wopbs_only::LEGACY_WOPBS_ONLY_4_BLOCKS_PARAM_MESSAGE_2_CARRY_2_KS_PBS;
        /// use tfhe::shortint::wopbs::WopbsKey;
        ///
        /// // Generate the client key and the server key:
        /// let (cks, sks) = gen_keys(LEGACY_WOPBS_ONLY_4_BLOCKS_PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        /// let std_sks = sks.as_view().try_into().unwrap();
        /// let wopbs_key = WopbsKey::new_wopbs_key_only_for_wopbs(cks.as_view().try_into().unwrap(), std_sks);
        /// let message_modulus = LEGACY_WOPBS_ONLY_4_BLOCKS_PARAM_MESSAGE_2_CARRY_2_KS_PBS.message_modulus.0;
        /// let m = 2;
        /// let ct = cks.encrypt_without_padding(m);
        /// let lut = wopbs_key.generate_lut(&ct, |x| x * x % message_modulus);
        /// let ct_res = wopbs_key.programmable_bootstrapping_without_padding(&ct, &lut);
        /// let res = cks.decrypt_without_padding(&ct_res);
        /// assert_eq!(res, (m * m) % message_modulus);
        /// ```
        pub fn generate_lut_without_padding<F>(&self, ct: &Ciphertext, f: F) -> Vec<u64>
        where
            F: Fn(u64) -> u64,
        {
            // The function is applied only on the message modulus bits
            let basis = ct.message_modulus.0 * ct.carry_modulus.0;
            let delta = 64 - f64::log2((basis) as f64).ceil() as u64;
            let poly_size = self
                .wopbs_server_key
                .atomic_pattern
                .bootstrapping_key
                .polynomial_size()
                .0;
            let mut vec_lut = vec![0; poly_size];
            for (i, value) in vec_lut.iter_mut().enumerate().take(basis as usize) {
                *value = f(i as u64 % ct.message_modulus.0) << delta;
            }
            vec_lut
        }

        /// Generate the Look-Up Table homomorphically using the WoPBS approach.
        ///
        ///
        /// # Example
        ///
        /// ```rust
        /// use tfhe::shortint::gen_keys;
        /// use tfhe::shortint::parameters::parameters_wopbs_message_carry::LEGACY_WOPBS_PARAM_MESSAGE_3_CARRY_3_KS_PBS;
        /// use tfhe::shortint::wopbs::WopbsKey;
        /// use tfhe::shortint::parameters::MessageModulus;
        ///
        /// // Generate the client key and the server key:
        /// let (cks, sks) = gen_keys(LEGACY_WOPBS_PARAM_MESSAGE_3_CARRY_3_KS_PBS);
        /// let wopbs_key = WopbsKey::new_wopbs_key_only_for_wopbs(cks.as_view().try_into().unwrap(),
        ///                                                        sks.as_view().try_into().unwrap());
        /// let message_modulus = MessageModulus(5);
        /// let m = 2;
        /// let ct = cks.encrypt_native_crt(m, message_modulus);
        /// let lut = wopbs_key.generate_lut_native_crt(&ct, |x| x * x % message_modulus.0);
        /// let ct_res = wopbs_key.programmable_bootstrapping_native_crt(&ct, &lut);
        /// let res = cks.decrypt_message_native_crt(&ct_res, message_modulus);
        /// assert_eq!(res, (m * m) % message_modulus.0);
        /// ```
        pub fn generate_lut_native_crt<F>(&self, ct: &Ciphertext, f: F) -> ShortintWopbsLUT
        where
            F: Fn(u64) -> u64,
        {
            // The function is applied only on the message modulus bits
            let basis = ct.message_modulus.0 * ct.carry_modulus.0;
            let nb_bit = f64::log2((basis) as f64).ceil() as u64;
            let poly_size = self
                .wopbs_server_key
                .atomic_pattern
                .bootstrapping_key
                .polynomial_size()
                .0;
            let mut lut = ShortintWopbsLUT::new(PlaintextCount(poly_size));
            for i in 0..basis {
                let index_lut = (((i % basis) << nb_bit) / basis) as usize;
                lut[index_lut] = (((f(i) % basis) as u128 * (1 << 64)) / basis as u128) as u64;
            }
            lut
        }

        /// Apply the Look-Up Table homomorphically using the WoPBS approach.
        ///
        /// #Warning: this assumes one bit of padding.
        ///
        /// # Example
        ///
        /// ```rust
        /// use rand::Rng;
        /// use tfhe::shortint::gen_keys;
        /// use tfhe::shortint::parameters::parameters_wopbs_message_carry::LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS;
        /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
        /// use tfhe::shortint::wopbs::*;
        ///
        /// // Generate the client key and the server key:
        /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        /// let std_sks = sks.as_view().try_into().unwrap();
        /// let std_cks = cks.as_view().try_into().unwrap();
        /// let wopbs_key = WopbsKey::new_wopbs_key(std_cks, std_sks, &LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        /// let mut rng = rand::rng();
        /// let message_modulus = LEGACY_WOPBS_PARAM_MESSAGE_2_CARRY_2_KS_PBS.message_modulus.0;
        /// let ct = cks.encrypt(rng.gen::<u64>() % message_modulus);
        /// let lut = vec![1_u64 << 59; wopbs_key.param.polynomial_size.0].into();
        /// let ct_res = wopbs_key.programmable_bootstrapping(&sks, &ct, &lut);
        /// let res = cks.decrypt_message_and_carry(&ct_res);
        /// assert_eq!(res, 1);
        /// ```
        pub fn programmable_bootstrapping(
            &self,
            sks: &ServerKey,
            ct_in: &Ciphertext,
            lut: &ShortintWopbsLUT,
        ) -> Ciphertext {
            let ct_wopbs = self.keyswitch_to_wopbs_params(sks, ct_in);
            let result_ct = self.wopbs(&ct_wopbs, lut);

            self.keyswitch_to_pbs_params(&result_ct)
        }

        /// Apply the Look-Up Table homomorphically using the WoPBS approach.
        ///
        /// #Warning: this assumes one bit of padding.
        /// #Warning: to use in a WoPBS context ONLY (i.e., non compliant with classical PBS)
        ///
        /// # Example
        ///
        /// ```rust
        /// use rand::Rng;
        /// use tfhe::shortint::gen_keys;
        /// use tfhe::shortint::parameters::parameters_wopbs_only::LEGACY_WOPBS_ONLY_4_BLOCKS_PARAM_MESSAGE_2_CARRY_2_KS_PBS;
        /// use tfhe::shortint::wopbs::*;
        ///
        /// // Generate the client key and the server key:
        /// let (cks, sks) = gen_keys(LEGACY_WOPBS_ONLY_4_BLOCKS_PARAM_MESSAGE_2_CARRY_2_KS_PBS);
        /// let std_sks = sks.as_view().try_into().unwrap();
        /// let std_cks = cks.as_view().try_into().unwrap();
        /// let wopbs_key = WopbsKey::new_wopbs_key_only_for_wopbs(std_cks, std_sks);
        /// let mut rng = rand::rng();
        /// let message_modulus = LEGACY_WOPBS_ONLY_4_BLOCKS_PARAM_MESSAGE_2_CARRY_2_KS_PBS.message_modulus.0;
        /// let ct = cks.encrypt(rng.gen::<u64>() % message_modulus);
        /// let lut = vec![1_u64 << 59; wopbs_key.param.polynomial_size.0].into();
        /// let ct_res = wopbs_key.wopbs(&ct, &lut);
        /// let res = cks.decrypt_message_and_carry(&ct_res);
        /// assert_eq!(res, 1);
        /// ```
        pub fn wopbs(&self, ct_in: &Ciphertext, lut: &ShortintWopbsLUT) -> Ciphertext {
            let tmp_sks = &self.wopbs_server_key;
            let message_modulus = tmp_sks.message_modulus.0;
            let carry_modulus = tmp_sks.carry_modulus.0;
            let delta = (1u64 << 63) / (carry_modulus * message_modulus);
            // casting to usize is fine, ilog2 of u64 is guaranteed to be < 64
            let delta_log = DeltaLog(delta.ilog2() as usize);
            let nb_bit_to_extract = f64::log2((message_modulus * carry_modulus) as f64) as usize;

            let ct_out = self.extract_bits_circuit_bootstrapping(
                ct_in,
                lut.as_ref(),
                delta_log,
                ExtractedBitsCount(nb_bit_to_extract),
            );

            ct_out
        }

        /// Apply the Look-Up Table homomorphically using the WoPBS approach.
        ///
        /// # Example
        ///
        /// ```rust
        /// use rand::Rng;
        /// use tfhe::shortint::gen_keys;
        /// use tfhe::shortint::parameters::parameters_wopbs::LEGACY_WOPBS_ONLY_8_BLOCKS_PARAM_MESSAGE_1_CARRY_1_KS_PBS;
        /// use tfhe::shortint::parameters::CarryModulus;
        /// use tfhe::shortint::wopbs::*;
        ///
        /// let mut msg_1_carry_0_params = LEGACY_WOPBS_ONLY_8_BLOCKS_PARAM_MESSAGE_1_CARRY_1_KS_PBS;
        /// msg_1_carry_0_params.carry_modulus = CarryModulus(1);
        /// let (cks, sks) = gen_keys(msg_1_carry_0_params);
        /// let std_sks = sks.as_view().try_into().unwrap();
        /// let std_cks = cks.as_view().try_into().unwrap();
        /// let wopbs_key = WopbsKey::new_wopbs_key_only_for_wopbs(std_cks, std_sks);
        /// let mut rng = rand::rng();
        /// let ct = cks.encrypt_without_padding(rng.gen::<u64>() % 2);
        /// let lut = vec![1_u64 << 63; wopbs_key.param.polynomial_size.0].into();
        /// let ct_res = wopbs_key.programmable_bootstrapping_without_padding(&ct, &lut);
        /// let res = cks.decrypt_message_and_carry_without_padding(&ct_res);
        /// assert_eq!(res, 1);
        /// ```
        pub fn programmable_bootstrapping_without_padding(
            &self,
            ct_in: &Ciphertext,
            lut: &ShortintWopbsLUT,
        ) -> Ciphertext {
            let sks = &self.wopbs_server_key;
            let message_modulus = sks.message_modulus.0;
            let carry_modulus = sks.carry_modulus.0;
            let delta = (1u64 << 63) / (carry_modulus * message_modulus) * 2;
            // casting to usize is fine, ilog2 of u64 is guaranteed to be < 64
            let delta_log = DeltaLog(delta.ilog2() as usize);

            let nb_bit_to_extract =
                f64::log2((sks.message_modulus.0 * sks.carry_modulus.0) as f64) as usize;

            let ciphertext = self.extract_bits_circuit_bootstrapping(
                ct_in,
                lut.as_ref(),
                delta_log,
                ExtractedBitsCount(nb_bit_to_extract),
            );

            ciphertext
        }

        /// Apply the Look-Up Table homomorphically using the WoPBS approach.
        ///
        /// # Example
        ///
        /// ```rust
        /// use tfhe::shortint::gen_keys;
        /// use tfhe::shortint::parameters::parameters_wopbs_message_carry::LEGACY_WOPBS_PARAM_MESSAGE_3_CARRY_3_KS_PBS;
        /// use tfhe::shortint::parameters::MessageModulus;
        /// use tfhe::shortint::wopbs::*;
        ///
        /// let (cks, sks) = gen_keys(LEGACY_WOPBS_PARAM_MESSAGE_3_CARRY_3_KS_PBS);
        /// let std_sks = sks.as_view().try_into().unwrap();
        /// let std_cks = cks.as_view().try_into().unwrap();
        /// let wopbs_key = WopbsKey::new_wopbs_key_only_for_wopbs(std_cks, std_sks);
        /// let msg = 2;
        /// let modulus = MessageModulus(5);
        /// let ct = cks.encrypt_native_crt(msg, modulus);
        /// let lut = wopbs_key.generate_lut_native_crt(&ct, |x| x);
        /// let ct_res = wopbs_key.programmable_bootstrapping_native_crt(&ct, &lut);
        /// let res = cks.decrypt_message_native_crt(&ct_res, modulus);
        /// assert_eq!(res, msg);
        /// ```
        pub fn programmable_bootstrapping_native_crt(
            &self,
            ct_in: &Ciphertext,
            lut: &ShortintWopbsLUT,
        ) -> Ciphertext {
            let nb_bit_to_extract =
                f64::log2((ct_in.message_modulus.0 * ct_in.carry_modulus.0) as f64).ceil() as usize;
            let delta_log = DeltaLog(64 - nb_bit_to_extract);

            // We need to add a corrective term, so clone the input
            let mut ct_in = ct_in.clone();

            // trick ( ct - delta/2 + delta/2^4  )
            lwe_ciphertext_plaintext_sub_assign(
                &mut ct_in.ct,
                Plaintext(
                    (1 << (64 - nb_bit_to_extract - 1)) - (1 << (64 - nb_bit_to_extract - 5)),
                ),
            );

            let ciphertext = self.extract_bits_circuit_bootstrapping(
                &ct_in,
                lut.as_ref(),
                delta_log,
                ExtractedBitsCount(nb_bit_to_extract),
            );

            ciphertext
        }

        /// Extract the given number of bits from a ciphertext.
        ///
        /// # Warning Experimental
        pub fn extract_bits(
            &self,
            delta_log: DeltaLog,
            ciphertext: &Ciphertext,
            num_bits_to_extract: ExtractedBitsCount,
        ) -> LweCiphertextListOwned<u64> {
            let server_key = &self.wopbs_server_key;

            let lwe_size = server_key
                .atomic_pattern
                .key_switching_key
                .output_key_lwe_dimension()
                .to_lwe_size();

            let mut output = LweCiphertextListOwned::new(
                0u64,
                lwe_size,
                LweCiphertextCount(num_bits_to_extract.0),
                self.param.ciphertext_modulus,
            );

            self.extract_bits_assign(delta_log, ciphertext, num_bits_to_extract, &mut output);

            output
        }

        /// Extract the given number of bits from a ciphertext.
        ///
        /// # Warning Experimental
        pub fn extract_bits_assign<OutputCont>(
            &self,
            delta_log: DeltaLog,
            ciphertext: &Ciphertext,
            num_bits_to_extract: ExtractedBitsCount,
            output: &mut LweCiphertextList<OutputCont>,
        ) where
            OutputCont: ContainerMut<Element = u64>,
        {
            let server_key = &self.wopbs_server_key;

            let bsk = &server_key.atomic_pattern.bootstrapping_key;
            let ksk = &server_key.atomic_pattern.key_switching_key;

            let fft = Fft::new(bsk.polynomial_size());
            let fft = fft.as_view();

            ShortintEngine::with_thread_local_mut(|engine| {
                let buffers = engine.get_computation_buffers();
                buffers.resize(
                    extract_bits_from_lwe_ciphertext_mem_optimized_requirement::<u64>(
                        ciphertext.ct.lwe_size().to_lwe_dimension(),
                        ksk.output_key_lwe_dimension(),
                        bsk.glwe_size(),
                        bsk.polynomial_size(),
                        fft,
                    )
                    .unaligned_bytes_required(),
                );

                let stack = buffers.stack();

                match bsk {
                    ShortintBootstrappingKey::Classic {
                        bsk,
                        modulus_switch_noise_reduction_key: _,
                    } => {
                        extract_bits_from_lwe_ciphertext_mem_optimized(
                            &ciphertext.ct,
                            output,
                            bsk,
                            ksk,
                            delta_log,
                            num_bits_to_extract,
                            fft,
                            stack,
                        );
                    }
                    ShortintBootstrappingKey::MultiBit { .. } => {
                        todo!("extract_bits_assign currently does not support multi-bit PBS")
                    }
                }
            });
        }

        /// Temporary wrapper.
        ///
        /// # Warning Experimental
        pub fn circuit_bootstrapping_vertical_packing<InputCont>(
            &self,
            vec_lut: &WopbsLUTBase,
            extracted_bits_blocks: &LweCiphertextList<InputCont>,
        ) -> Vec<LweCiphertextOwned<u64>>
        where
            InputCont: Container<Element = u64>,
        {
            let output_list = self.circuit_bootstrap_with_bits(
                extracted_bits_blocks,
                &vec_lut.lut(),
                LweCiphertextCount(vec_lut.output_ciphertext_count().0),
            );

            assert_eq!(
                output_list.lwe_ciphertext_count().0,
                vec_lut.output_ciphertext_count().0
            );

            let output_container = output_list.into_container();
            let ciphertext_modulus = self.param.ciphertext_modulus;
            let lwes: Vec<_> = output_container
                .chunks_exact(output_container.len() / vec_lut.output_ciphertext_count().0)
                .map(|s| LweCiphertextOwned::from_container(s.to_vec(), ciphertext_modulus))
                .collect();

            assert_eq!(lwes.len(), vec_lut.output_ciphertext_count().0);
            lwes
        }

        pub fn keyswitch_to_pbs_params(&self, ct_in: &Ciphertext) -> Ciphertext {
            // move to wopbs parameters to pbs parameters
            //Keyswitch-PBS:
            // 1. KS to go back to the original encryption key
            // 2. PBS to remove the noise added by the previous KS
            //
            let acc = self.pbs_server_key.generate_lookup_table(|x| x);

            ShortintEngine::with_thread_local_mut(|engine| {
                let (mut ciphertext_buffer, buffers) = engine.get_buffers(
                    self.pbs_server_key
                        .atomic_pattern
                        .intermediate_lwe_dimension(),
                    self.pbs_server_key.atomic_pattern.ciphertext_modulus(),
                );
                // Compute a key switch
                keyswitch_lwe_ciphertext(
                    &self.pbs_server_key.atomic_pattern.key_switching_key,
                    &ct_in.ct,
                    &mut ciphertext_buffer,
                );

                let ct_out = match &self.pbs_server_key.atomic_pattern.bootstrapping_key {
                    ShortintBootstrappingKey::Classic {
                        bsk: fourier_bsk,
                        modulus_switch_noise_reduction_key: _,
                    } => {
                        let out_lwe_size = fourier_bsk.output_lwe_dimension().to_lwe_size();
                        let mut ct_out =
                            LweCiphertextOwned::new(0, out_lwe_size, self.param.ciphertext_modulus);

                        let fft = Fft::new(fourier_bsk.polynomial_size());
                        let fft = fft.as_view();
                        buffers.resize(
                            programmable_bootstrap_lwe_ciphertext_mem_optimized_requirement::<u64>(
                                fourier_bsk.glwe_size(),
                                fourier_bsk.polynomial_size(),
                                fft,
                            )
                            .unaligned_bytes_required(),
                        );
                        let stack = buffers.stack();

                        // Compute a bootstrap
                        programmable_bootstrap_lwe_ciphertext_mem_optimized(
                            &ciphertext_buffer,
                            &mut ct_out,
                            &acc.acc,
                            fourier_bsk,
                            fft,
                            stack,
                        );

                        ct_out
                    }
                    ShortintBootstrappingKey::MultiBit { .. } => {
                        return Err(WopbsKeyCreationError::UnsupportedMultiBit);
                    }
                };
                Ok(Ciphertext::new(
                    ct_out,
                    ct_in.degree,
                    NoiseLevel::NOMINAL,
                    ct_in.message_modulus,
                    ct_in.carry_modulus,
                    ct_in.atomic_pattern,
                ))
            })
            .unwrap()
        }

        pub fn keyswitch_to_wopbs_params(&self, sks: &ServerKey, ct_in: &Ciphertext) -> Ciphertext {
            // First PBS to remove the noise
            let acc = sks.generate_lookup_table(|x| x);
            let ct_clean = sks.apply_lookup_table(ct_in, &acc);

            let mut buffer_lwe_after_ks = LweCiphertextOwned::new(
                0,
                self.ksk_pbs_to_wopbs
                    .output_key_lwe_dimension()
                    .to_lwe_size(),
                self.param.ciphertext_modulus,
            );

            // Compute a key switch
            keyswitch_lwe_ciphertext(
                &self.ksk_pbs_to_wopbs,
                &ct_clean.ct,
                &mut buffer_lwe_after_ks,
            );

            // The identity lut wrongly sets the max degree in the ciphertext, when in reality the
            // degree of the ciphertext has no changed, we manage this case manually here
            Ciphertext::new(
                buffer_lwe_after_ks,
                ct_in.degree,
                NoiseLevel::NOMINAL,
                ct_clean.message_modulus,
                ct_clean.carry_modulus,
                ct_in.atomic_pattern,
            )
        }

        pub(crate) fn circuit_bootstrap_with_bits<InputCont, LutCont>(
            &self,
            extracted_bits: &LweCiphertextList<InputCont>,
            lut: &PlaintextList<LutCont>,
            count: LweCiphertextCount,
        ) -> LweCiphertextListOwned<u64>
        where
            InputCont: Container<Element = u64>,
            LutCont: Container<Element = u64>,
        {
            let sks = &self.wopbs_server_key;
            let fourier_bsk = &sks.atomic_pattern.bootstrapping_key;

            let output_lwe_size = fourier_bsk.output_lwe_dimension().to_lwe_size();

            let mut output_cbs_vp_ct = LweCiphertextListOwned::new(
                0u64,
                output_lwe_size,
                count,
                self.param.ciphertext_modulus,
            );
            let lut =
                PolynomialListView::from_container(lut.as_ref(), fourier_bsk.polynomial_size());

            let fft = Fft::new(fourier_bsk.polynomial_size());
            let fft = fft.as_view();

            ShortintEngine::with_thread_local_mut(|engine| {
                let buffers = engine.get_computation_buffers();
                buffers.resize(
                    circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized_requirement::<u64>(
                        extracted_bits.lwe_ciphertext_count(),
                        output_cbs_vp_ct.lwe_ciphertext_count(),
                        extracted_bits.lwe_size(),
                        lut.polynomial_count(),
                        fourier_bsk.output_lwe_dimension().to_lwe_size(),
                        fourier_bsk.glwe_size(),
                        self.cbs_pfpksk.output_polynomial_size(),
                        self.param.cbs_level,
                        fft,
                    )
                        .unaligned_bytes_required(),
                );

                let stack = buffers.stack();

                match &sks.atomic_pattern.bootstrapping_key {
                    ShortintBootstrappingKey::Classic{bsk, modulus_switch_noise_reduction_key:_ } => {
                        circuit_bootstrap_boolean_vertical_packing_lwe_ciphertext_list_mem_optimized(
                            extracted_bits,
                            &mut output_cbs_vp_ct,
                            &lut,
                            bsk,
                            &self.cbs_pfpksk,
                            self.param.cbs_base_log,
                            self.param.cbs_level,
                            fft,
                            stack,
                        );
                    }
                    ShortintBootstrappingKey::MultiBit { .. } => {
                        return Err(WopbsKeyCreationError::UnsupportedMultiBit);
                    }
                }
                Ok(())
            }).unwrap();

            output_cbs_vp_ct
        }

        pub(crate) fn extract_bits_circuit_bootstrapping(
            &self,
            ct_in: &Ciphertext,
            lut: &WopbsLUTBase,
            delta_log: DeltaLog,
            nb_bit_to_extract: ExtractedBitsCount,
        ) -> Ciphertext {
            let extracted_bits = self.extract_bits(delta_log, ct_in, nb_bit_to_extract);

            let ciphertext_list = self.circuit_bootstrap_with_bits(
                &extracted_bits,
                &lut.lut(),
                LweCiphertextCount(1),
            );

            // Here the output list contains a single ciphertext, we can consume the container to
            // convert it to a single ciphertext
            let ciphertext = LweCiphertextOwned::from_container(
                ciphertext_list.into_container(),
                self.param.ciphertext_modulus,
            );

            let sks = &self.wopbs_server_key;

            Ciphertext::new(
                ciphertext,
                Degree::new(sks.message_modulus.0 - 1),
                NoiseLevel::NOMINAL,
                sks.message_modulus,
                sks.carry_modulus,
                ct_in.atomic_pattern,
            )
        }
    }
}
