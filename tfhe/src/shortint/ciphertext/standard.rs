//! Module with the definition of the Ciphertext.
use super::super::parameters::CiphertextConformanceParams;
use super::common::*;
use crate::conformance::ParameterSetConformant;
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::{allocate_and_trivially_encrypt_new_lwe_ciphertext, LweSize};
use crate::shortint::backward_compatibility::ciphertext::CiphertextVersions;
use crate::shortint::ciphertext::ReRandomizationSeed;
use crate::shortint::key_switching_key::KeySwitchingKeyMaterialView;
use crate::shortint::parameters::{AtomicPatternKind, CarryModulus, MessageModulus};
use crate::shortint::public_key::compact::CompactPublicKey;
use crate::shortint::{CiphertextModulus, PaddingBit, ShortintEncoding};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use tfhe_versionable::Versionize;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(CiphertextVersions)]
#[must_use]
pub struct Ciphertext {
    pub ct: LweCiphertextOwned<u64>,
    pub degree: Degree,
    // For correctness reasons this field MUST remain private, this forces the use of the accessor
    // which has noise checks enabled on demand
    noise_level: NoiseLevel,
    pub message_modulus: MessageModulus,
    pub carry_modulus: CarryModulus,
    pub atomic_pattern: AtomicPatternKind,
}

impl crate::named::Named for Ciphertext {
    const NAME: &'static str = "shortint::Ciphertext";
}

impl ParameterSetConformant for Ciphertext {
    type ParameterSet = CiphertextConformanceParams;

    fn is_conformant(&self, param: &CiphertextConformanceParams) -> bool {
        let Self {
            ct,
            degree,
            noise_level,
            message_modulus,
            carry_modulus,
            atomic_pattern,
        } = self;

        ct.is_conformant(&param.ct_params)
            && *message_modulus == param.message_modulus
            && *carry_modulus == param.carry_modulus
            && *atomic_pattern == param.atomic_pattern
            && *degree == param.degree
            && *noise_level == param.noise_level
    }
}

// Use destructuring to also have a compile error
// if ever a new member is added to Ciphertext
// and is not handled here.
//
// And a warning if a member is destructured but not used.
impl Clone for Ciphertext {
    fn clone(&self) -> Self {
        let Self {
            ct: src_ct,
            degree: src_degree,
            message_modulus: src_message_modulus,
            carry_modulus: src_carry_modulus,
            atomic_pattern: src_atomic_pattern,
            noise_level: src_noise_level,
        } = self;

        Self {
            ct: src_ct.clone(),
            degree: *src_degree,
            message_modulus: *src_message_modulus,
            carry_modulus: *src_carry_modulus,
            atomic_pattern: *src_atomic_pattern,
            noise_level: *src_noise_level,
        }
    }

    fn clone_from(&mut self, source: &Self) {
        let Self {
            ct: dst_ct,
            degree: dst_degree,
            message_modulus: dst_message_modulus,
            carry_modulus: dst_carry_modulus,
            atomic_pattern: dst_atomic_pattern,
            noise_level: dst_noise_level,
        } = self;

        let Self {
            ct: src_ct,
            degree: src_degree,
            message_modulus: src_message_modulus,
            carry_modulus: src_carry_modulus,
            atomic_pattern: src_atomic_pattern,
            noise_level: src_noise_level,
        } = source;

        if dst_ct.ciphertext_modulus() != src_ct.ciphertext_modulus()
            || dst_ct.lwe_size() != src_ct.lwe_size()
        {
            *dst_ct = src_ct.clone();
        } else {
            dst_ct.as_mut().copy_from_slice(src_ct.as_ref());
        }
        *dst_degree = *src_degree;
        *dst_message_modulus = *src_message_modulus;
        *dst_carry_modulus = *src_carry_modulus;
        *dst_atomic_pattern = *src_atomic_pattern;
        *dst_noise_level = *src_noise_level;
    }
}

impl Ciphertext {
    pub fn new(
        ct: LweCiphertextOwned<u64>,
        degree: Degree,
        noise_level: NoiseLevel,
        message_modulus: MessageModulus,
        carry_modulus: CarryModulus,
        atomic_pattern: AtomicPatternKind,
    ) -> Self {
        Self {
            ct,
            degree,
            noise_level,
            message_modulus,
            carry_modulus,
            atomic_pattern,
        }
    }
    pub fn carry_is_empty(&self) -> bool {
        self.degree.get() < self.message_modulus.0
    }

    pub fn is_trivial(&self) -> bool {
        self.noise_level() == NoiseLevel::ZERO
            && self.ct.get_mask().as_ref().iter().all(|&x| x == 0u64)
    }

    pub fn noise_level(&self) -> NoiseLevel {
        self.noise_level
    }

    #[cfg_attr(any(feature = "noise-asserts", test), track_caller)]
    pub fn set_noise_level(&mut self, noise_level: NoiseLevel, max_noise_level: MaxNoiseLevel) {
        if cfg!(feature = "noise-asserts") || cfg!(test) {
            max_noise_level.validate(noise_level).unwrap()
        } else {
            let _ = max_noise_level;
        }
        self.noise_level = noise_level;
    }

    pub fn set_noise_level_to_nominal(&mut self) {
        self.noise_level = NoiseLevel::NOMINAL;
    }

    /// Decrypts a trivial ciphertext
    ///
    /// Trivial ciphertexts are ciphertexts which are not encrypted
    /// meaning they can be decrypted by any key, or even without a key.
    ///
    /// For debugging it can be useful to use trivial ciphertext to speed up
    /// execution, and use [Self::decrypt_trivial] to decrypt temporary values
    /// and debug.
    ///
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
    /// let msg = 1;
    /// let msg2 = 2;
    ///
    /// // Trivial encryption
    /// let trivial_ct = sks.create_trivial(msg);
    /// let non_trivial_ct = cks.encrypt(msg2);
    ///
    /// let res = trivial_ct.decrypt_trivial();
    /// assert_eq!(Ok(1), res);
    ///
    /// let res = non_trivial_ct.decrypt_trivial();
    /// assert!(res.is_err());
    ///
    /// // Doing operations that mixes trivial and non trivial
    /// // will always return a non trivial
    /// let ct_res = sks.add(&trivial_ct, &non_trivial_ct);
    /// let res = ct_res.decrypt_trivial();
    /// assert!(res.is_err());
    ///
    /// // Doing operations using only trivial ciphertexts
    /// // will return a trivial
    /// let ct_res = sks.add(&trivial_ct, &trivial_ct);
    /// let res = ct_res.decrypt_trivial();
    /// assert_eq!(Ok(2), res);
    /// ```
    pub fn decrypt_trivial(&self) -> Result<u64, NotTrivialCiphertextError> {
        self.decrypt_trivial_message_and_carry()
            .map(|x| x % self.message_modulus.0)
    }

    pub(crate) fn encoding(&self, padding_bit: PaddingBit) -> ShortintEncoding<u64> {
        ShortintEncoding {
            ciphertext_modulus: self.ct.ciphertext_modulus(),
            message_modulus: self.message_modulus,
            carry_modulus: self.carry_modulus,
            padding_bit,
        }
    }

    /// See [Self::decrypt_trivial].
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::gen_keys;
    /// use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// let msg = 2u64;
    /// let clear = 3u64;
    ///
    /// let mut trivial_ct = sks.create_trivial(msg);
    ///
    /// sks.unchecked_scalar_add_assign(&mut trivial_ct, clear as u8);
    ///
    /// let res = trivial_ct.decrypt_trivial();
    /// let expected = (msg + clear) % PARAM_MESSAGE_2_CARRY_2_KS_PBS.message_modulus.0;
    /// assert_eq!(Ok(expected), res);
    ///
    /// let res = trivial_ct.decrypt_trivial_message_and_carry();
    /// assert_eq!(Ok(msg + clear), res);
    /// ```
    pub fn decrypt_trivial_message_and_carry(&self) -> Result<u64, NotTrivialCiphertextError> {
        if self.is_trivial() {
            let decoded = self
                .encoding(PaddingBit::Yes)
                .decode(Plaintext(*self.ct.get_body().data))
                .0;
            Ok(decoded)
        } else {
            Err(NotTrivialCiphertextError)
        }
    }

    /// This function can be called after decompressing a [`Ciphertext`] from a
    /// [`CompressedCiphertextList`](super::compressed_ciphertext_list::CompressedCiphertextList) to
    /// re-randomize it before any computations.
    ///
    /// This function only supports [`PBSOrder::KeyswitchBootstrap`] ordered
    /// [`Ciphertext`]/[`ServerKey`](crate::shortint::ServerKey).
    ///
    /// It uses a [`CompactPublicKey`] to generate a new encryption of 0, a
    /// [`KeySwitchingKeyMaterialView`] is required to keyswitch between the secret key used to
    /// generate the [`CompactPublicKey`] to the "big"/post PBS/GLWE secret key from the
    /// [`ServerKey`](crate::shortint::ServerKey).
    pub fn re_randomize_with_compact_public_key_encryption(
        &mut self,
        compact_public_key: &CompactPublicKey,
        key_switching_key_material: &KeySwitchingKeyMaterialView<'_>,
        seed: ReRandomizationSeed,
    ) -> crate::Result<()> {
        compact_public_key.re_randomize_ciphertexts(
            std::slice::from_mut(self),
            key_switching_key_material,
            seed,
        )
    }
}

pub(crate) fn unchecked_create_trivial_with_lwe_size(
    value: Cleartext<u64>,
    lwe_size: LweSize,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    atomic_pattern: AtomicPatternKind,
    ciphertext_modulus: CiphertextModulus,
) -> Ciphertext {
    let encoded = ShortintEncoding {
        ciphertext_modulus,
        message_modulus,
        carry_modulus,
        padding_bit: PaddingBit::Yes,
    }
    .encode(value);

    let ct =
        allocate_and_trivially_encrypt_new_lwe_ciphertext(lwe_size, encoded, ciphertext_modulus);

    let degree = Degree::new(value.0);

    Ciphertext::new(
        ct,
        degree,
        NoiseLevel::ZERO,
        message_modulus,
        carry_modulus,
        atomic_pattern,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shortint::ciphertext::ReRandomizationContext;
    use crate::shortint::key_switching_key::KeySwitchingKeyBuildHelper;
    use crate::shortint::keycache::KEY_CACHE;
    use crate::shortint::parameters::test_params::{
        TEST_META_PARAM_CPU_2_2_KS32_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
        TEST_META_PARAM_PROD_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128,
    };
    use crate::shortint::parameters::MetaParameters;
    use crate::shortint::public_key::compact::CompactPrivateKey;
    use crate::shortint::server_key::tests::parameterized_test::create_parameterized_test;
    use crate::shortint::CiphertextModulus;

    #[test]
    fn test_clone_from_same_lwe_size_and_modulus_ci_run_filter() {
        let mut c1 = Ciphertext {
            ct: LweCiphertextOwned::from_container(
                vec![1u64; 256],
                CiphertextModulus::new_native(),
            ),
            degree: Degree::new(1),
            message_modulus: MessageModulus(1),
            carry_modulus: CarryModulus(1),
            atomic_pattern: AtomicPatternKind::Standard(PBSOrder::KeyswitchBootstrap),
            noise_level: NoiseLevel::NOMINAL,
        };

        let c2 = Ciphertext {
            ct: LweCiphertextOwned::from_container(
                vec![2323858949u64; 256],
                CiphertextModulus::new_native(),
            ),
            degree: Degree::new(42),
            message_modulus: MessageModulus(2),
            carry_modulus: CarryModulus(2),
            atomic_pattern: AtomicPatternKind::Standard(PBSOrder::BootstrapKeyswitch),
            noise_level: NoiseLevel::NOMINAL,
        };

        assert_ne!(c1, c2);

        c1.clone_from(&c2);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_clone_from_same_lwe_size_different_modulus_ci_run_filter() {
        let mut c1 = Ciphertext {
            ct: LweCiphertextOwned::from_container(
                vec![1u64; 256],
                CiphertextModulus::try_new_power_of_2(32).unwrap(),
            ),
            degree: Degree::new(1),
            message_modulus: MessageModulus(1),
            carry_modulus: CarryModulus(1),
            atomic_pattern: AtomicPatternKind::Standard(PBSOrder::KeyswitchBootstrap),
            noise_level: NoiseLevel::NOMINAL,
        };

        let c2 = Ciphertext {
            ct: LweCiphertextOwned::from_container(
                vec![2323858949u64; 256],
                CiphertextModulus::new_native(),
            ),
            degree: Degree::new(42),
            message_modulus: MessageModulus(2),
            carry_modulus: CarryModulus(2),
            atomic_pattern: AtomicPatternKind::Standard(PBSOrder::BootstrapKeyswitch),
            noise_level: NoiseLevel::NOMINAL,
        };

        assert_ne!(c1, c2);

        c1.clone_from(&c2);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_clone_from_different_lwe_size_same_modulus_ci_run_filter() {
        let mut c1 = Ciphertext {
            ct: LweCiphertextOwned::from_container(
                vec![1u64; 512],
                CiphertextModulus::new_native(),
            ),
            degree: Degree::new(1),
            message_modulus: MessageModulus(1),
            carry_modulus: CarryModulus(1),
            atomic_pattern: AtomicPatternKind::Standard(PBSOrder::KeyswitchBootstrap),
            noise_level: NoiseLevel::NOMINAL,
        };

        let c2 = Ciphertext {
            ct: LweCiphertextOwned::from_container(
                vec![2323858949u64; 256],
                CiphertextModulus::new_native(),
            ),
            degree: Degree::new(42),
            message_modulus: MessageModulus(2),
            carry_modulus: CarryModulus(2),
            atomic_pattern: AtomicPatternKind::Standard(PBSOrder::BootstrapKeyswitch),
            noise_level: NoiseLevel::NOMINAL,
        };

        assert_ne!(c1, c2);

        c1.clone_from(&c2);
        assert_eq!(c1, c2);
    }

    fn test_re_randomize_ciphertext(meta_params: MetaParameters) {
        let params = meta_params.compute_parameters;
        let comp_params = meta_params
            .compression_parameters
            .expect("MetaParameters should have compression_parameters");
        let dedicated_cpk_params = meta_params
            .dedicated_compact_public_key_parameters
            .expect("MetaParameters should have dedicated_compact_public_key_parameters");
        let cpk_params = dedicated_cpk_params.pke_params;
        let ks_params = dedicated_cpk_params.ksk_params;

        let key_entry = KEY_CACHE.get_from_param(params);
        // Generate the client key and the server key:
        let (cks, sks) = (key_entry.client_key(), key_entry.server_key());
        let cpk_private_key = CompactPrivateKey::new(cpk_params);
        let cpk = CompactPublicKey::new(&cpk_private_key);
        let ksk_material =
            KeySwitchingKeyBuildHelper::new((&cpk_private_key, None), (cks, sks), ks_params)
                .key_switching_key_material;
        let ksk_material = ksk_material.as_view();

        let private_compression_key = cks.new_compression_private_key(comp_params);
        let (compression_key, decompression_key) =
            cks.new_compression_decompression_keys(&private_compression_key);

        let msg = cks.parameters().message_modulus().0 - 1;

        for _ in 0..10 {
            let ct = cks.encrypt(msg);

            let compressed = compression_key.compress_ciphertexts_into_list(&[ct]);

            let decompressed = decompression_key.unpack(&compressed, 0).unwrap();

            let mut re_randomizer_context = ReRandomizationContext::new(*b"TFHE_Rrd", *b"TFHE_Enc");
            re_randomizer_context.add_ciphertext(&decompressed);

            let mut seed_gen = re_randomizer_context.finalize();

            let seed = seed_gen.next_seed();

            let mut re_randomized = decompressed.clone();
            re_randomized
                .re_randomize_with_compact_public_key_encryption(&cpk, &ksk_material, seed)
                .unwrap();

            assert_ne!(decompressed, re_randomized);

            let pbsed = sks.bitand(&re_randomized, &re_randomized);

            let dec = cks.decrypt_message_and_carry(&pbsed);

            assert_eq!(dec, msg);
        }
    }

    create_parameterized_test!(test_re_randomize_ciphertext {
        (TEST_META_PARAM_PROD_CPU_2_2_KS_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128, CPU_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128),
        (TEST_META_PARAM_CPU_2_2_KS32_PBS_PKE_TO_SMALL_ZKV2_TUNIFORM_2M128, CPU_MESSAGE_2_CARRY_2_KS32_PBS_TUNIFORM_2M128)
    });
}
