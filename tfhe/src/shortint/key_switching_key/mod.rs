//! This module defines KeySwitchingKey
//!
//! - [KeySwitchingKey] allows switching the keys of a ciphertext, from a cleitn key to another.

use crate::core_crypto::prelude::{
    decompress_seeded_lwe_keyswitch_key, keyswitch_lwe_ciphertext, ActivatedRandomGenerator,
    LweKeyswitchKeyOwned, SeededLweKeyswitchKeyOwned,
};
use crate::shortint::ciphertext::Degree;
use crate::shortint::client_key::secret_encryption_key::SecretEncryptionKeyView;
use crate::shortint::engine::ShortintEngine;
use crate::shortint::parameters::{
    EncryptionKeyChoice, NoiseLevel, PBSOrder, ShortintKeySwitchingParameters,
};
use crate::shortint::server_key::apply_programmable_bootstrap;
use crate::shortint::{Ciphertext, ClientKey, CompressedServerKey, ServerKey};
use core::cmp::Ordering;
use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

use super::backward_compatibility::key_switching_key::{
    CompressedKeySwitchingKeyMaterialVersions, KeySwitchingKeyMaterialVersions,
};

#[cfg(test)]
mod test;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(KeySwitchingKeyMaterialVersions)]
pub struct KeySwitchingKeyMaterial {
    pub(crate) key_switching_key: LweKeyswitchKeyOwned<u64>,
    pub(crate) cast_rshift: i8,
    pub(crate) destination_key: EncryptionKeyChoice,
}

impl KeySwitchingKeyMaterial {
    pub fn as_view(&self) -> KeySwitchingKeyMaterialView<'_> {
        KeySwitchingKeyMaterialView {
            key_switching_key: &self.key_switching_key,
            cast_rshift: self.cast_rshift,
            destination_key: self.destination_key,
        }
    }
}

// This is used to have the ability to build a keyswitching key without owning the ServerKey
// It is a bit of a hack, but at this point it seems ok
pub(crate) struct KeySwitchingKeyBuildHelper<'keys> {
    pub(crate) key_switching_key_material: KeySwitchingKeyMaterial,
    pub(crate) dest_server_key: &'keys ServerKey,
    pub(crate) src_server_key: Option<&'keys ServerKey>,
}

/// A structure containing the casting public key.
///
/// The casting key is generated by the client and is meant to be published: the client
/// sends it to the server so it can cast from one set of parameters to another.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeySwitchingKey {
    pub(crate) key_switching_key_material: KeySwitchingKeyMaterial,
    pub(crate) dest_server_key: ServerKey,
    pub(crate) src_server_key: Option<ServerKey>,
}

impl<'keys> From<KeySwitchingKeyBuildHelper<'keys>> for KeySwitchingKey {
    fn from(value: KeySwitchingKeyBuildHelper) -> Self {
        let KeySwitchingKeyBuildHelper {
            key_switching_key_material,
            dest_server_key,
            src_server_key,
        } = value;

        Self {
            key_switching_key_material,
            dest_server_key: dest_server_key.to_owned(),
            src_server_key: src_server_key.map(ToOwned::to_owned),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeySwitchingKeyMaterialView<'key> {
    pub(crate) key_switching_key: &'key LweKeyswitchKeyOwned<u64>,
    pub(crate) cast_rshift: i8,
    pub(crate) destination_key: EncryptionKeyChoice,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct KeySwitchingKeyView<'keys> {
    pub(crate) key_switching_key_material: KeySwitchingKeyMaterialView<'keys>,
    pub(crate) dest_server_key: &'keys ServerKey,
    pub(crate) src_server_key: Option<&'keys ServerKey>,
}

impl<'keys> KeySwitchingKeyBuildHelper<'keys> {
    pub(crate) fn new<'input_key, InputEncryptionKey>(
        input_key_pair: (InputEncryptionKey, Option<&'keys ServerKey>),
        output_key_pair: (&'keys ClientKey, &'keys ServerKey),
        params: ShortintKeySwitchingParameters,
    ) -> Self
    where
        InputEncryptionKey: Into<SecretEncryptionKeyView<'input_key>>,
    {
        let input_secret_key: SecretEncryptionKeyView<'_> = input_key_pair.0.into();

        // Creation of the key switching key
        let key_switching_key = ShortintEngine::with_thread_local_mut(|engine| {
            engine.new_key_switching_key(&input_secret_key, output_key_pair.0, params)
        });

        let full_message_modulus_input =
            input_secret_key.carry_modulus.0 * input_secret_key.message_modulus.0;
        let full_message_modulus_output = output_key_pair.0.parameters.carry_modulus().0
            * output_key_pair.0.parameters.message_modulus().0;
        assert!(
            full_message_modulus_input.is_power_of_two()
                && full_message_modulus_output.is_power_of_two(),
            "Cannot create casting key if the full messages moduli are not a power of 2"
        );
        if full_message_modulus_input > full_message_modulus_output {
            assert!(
                input_key_pair.1.is_some(),
                "Trying to build a shortint::KeySwitchingKey \
                going from a large modulus {full_message_modulus_input} \
                to a smaller modulus {full_message_modulus_output} \
                without providing a source ServerKey, this is not supported"
            );
        }

        let nb_bits_input: i8 = full_message_modulus_input.ilog2().try_into().unwrap();
        let nb_bits_output: i8 = full_message_modulus_output.ilog2().try_into().unwrap();

        // Pack the keys in the casting key set:
        Self {
            key_switching_key_material: KeySwitchingKeyMaterial {
                key_switching_key,
                cast_rshift: nb_bits_output - nb_bits_input,
                destination_key: params.destination_key,
            },
            dest_server_key: output_key_pair.1,
            src_server_key: input_key_pair.1,
        }
    }
}

impl KeySwitchingKey {
    /// Generate a casting key. This can cast to several kinds of keys (shortint, integer, hlapi),
    /// depending on input.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_1_CARRY_1_KS_PBS, PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    /// };
    /// use tfhe::shortint::prelude::*;
    /// use tfhe::shortint::{gen_keys, KeySwitchingKey};
    ///
    /// // Generate the client keys and server keys:
    /// let (ck1, sk1) = gen_keys(PARAM_MESSAGE_1_CARRY_1_KS_PBS);
    /// let (ck2, sk2) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// // Generate the server key:
    /// let ksk = KeySwitchingKey::new(
    ///     (&ck1, Some(&sk1)),
    ///     (&ck2, &sk2),
    ///     PARAM_KEYSWITCH_1_1_KS_PBS_TO_2_2_KS_PBS,
    /// );
    /// ```
    pub fn new<'input_key, InputEncryptionKey>(
        input_key_pair: (InputEncryptionKey, Option<&ServerKey>),
        output_key_pair: (&ClientKey, &ServerKey),
        params: ShortintKeySwitchingParameters,
    ) -> Self
    where
        InputEncryptionKey: Into<SecretEncryptionKeyView<'input_key>>,
    {
        KeySwitchingKeyBuildHelper::new(input_key_pair, output_key_pair, params).into()
    }

    pub fn as_view(&self) -> KeySwitchingKeyView<'_> {
        let Self {
            key_switching_key_material,
            dest_server_key,
            src_server_key,
        } = self;

        KeySwitchingKeyView {
            key_switching_key_material: key_switching_key_material.as_view(),
            dest_server_key,
            src_server_key: src_server_key.as_ref(),
        }
    }

    /// Deconstruct a [`KeySwitchingKey`] into its constituents.
    pub fn into_raw_parts(self) -> (KeySwitchingKeyMaterial, ServerKey, Option<ServerKey>) {
        let Self {
            key_switching_key_material,
            dest_server_key,
            src_server_key,
        } = self;

        (key_switching_key_material, dest_server_key, src_server_key)
    }

    /// Construct a [`KeySwitchingKey`] from its constituents.
    ///
    /// # Panics
    ///
    /// Panics if the provided raw parts are not compatible with each other, i.e.:
    ///
    /// if the provided source [`ServerKey`] ciphertext
    /// [`LweDimension`](`crate::core_crypto::commons::parameters::LweDimension`) does not match the
    /// input [`LweDimension`](`crate::core_crypto::commons::parameters::LweDimension`) of the
    /// [`LweKeyswitchKeyOwned`] in the provided [`KeySwitchingKeyMaterial`] or if the provided
    /// destination [`ServerKey`] ciphertext
    /// [`LweDimension`](`crate::core_crypto::commons::parameters::LweDimension`) does not match
    /// the output [`LweDimension`](`crate::core_crypto::commons::parameters::LweDimension`) of
    /// the [`LweKeyswitchKeyOwned`] in the provided [`KeySwitchingKeyMaterial`].
    pub fn from_raw_parts(
        key_switching_key_material: KeySwitchingKeyMaterial,
        dest_server_key: ServerKey,
        src_server_key: Option<ServerKey>,
    ) -> Self {
        match src_server_key {
            Some(ref src_server_key) => {
                let src_lwe_dimension = src_server_key.ciphertext_lwe_dimension();

                assert_eq!(
                    src_lwe_dimension,
                    key_switching_key_material
                        .key_switching_key
                        .input_key_lwe_dimension(),
                    "Mismatch between the source ServerKey ciphertext LweDimension ({:?}) \
                    and the LweKeyswitchKey input LweDimension ({:?})",
                    src_lwe_dimension,
                    key_switching_key_material
                        .key_switching_key
                        .input_key_lwe_dimension(),
                );

                assert_eq!(
                    src_server_key.ciphertext_modulus, dest_server_key.ciphertext_modulus,
                    "Mismatch between the source ServerKey CiphertextModulus ({:?}) \
                    and the destination ServerKey CiphertextModulus ({:?})",
                    src_server_key.ciphertext_modulus, dest_server_key.ciphertext_modulus,
                );
            }
            None => assert!(
                key_switching_key_material.cast_rshift >= 0,
                "Trying to build a shortint::KeySwitchingKey with a negative cast_rshift \
                without providing a source ServerKey, this is not supported"
            ),
        }

        let dst_lwe_dimension = match key_switching_key_material.destination_key {
            EncryptionKeyChoice::Big => dest_server_key.bootstrapping_key.output_lwe_dimension(),
            EncryptionKeyChoice::Small => dest_server_key.bootstrapping_key.input_lwe_dimension(),
        };

        assert_eq!(
            dst_lwe_dimension,
            key_switching_key_material
                .key_switching_key
                .output_key_lwe_dimension(),
            "Mismatch between the destination ServerKey ciphertext LweDimension ({:?}) \
            and the LweKeyswitchKey output LweDimension ({:?})",
            dst_lwe_dimension,
            key_switching_key_material
                .key_switching_key
                .output_key_lwe_dimension(),
        );
        assert_eq!(
            key_switching_key_material
                .key_switching_key
                .ciphertext_modulus(),
            dest_server_key.ciphertext_modulus,
            "Mismatch between the LweKeyswitchKey CiphertextModulus ({:?}) \
            and the destination ServerKey CiphertextModulus ({:?})",
            key_switching_key_material
                .key_switching_key
                .ciphertext_modulus(),
            dest_server_key.ciphertext_modulus,
        );

        Self {
            key_switching_key_material,
            dest_server_key,
            src_server_key,
        }
    }

    /// Cast a ciphertext from the source parameter set to the dest parameter set,
    /// returning a new ciphertext.
    ///
    /// # Example (the following code won't actually run because this function is private)
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_1_CARRY_1_KS_PBS, PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    /// };
    /// use tfhe::shortint::prelude::*;
    /// use tfhe::shortint::{gen_keys, KeySwitchingKey};
    ///
    /// // Generate the client keys and server keys:
    /// let (ck1, sk1) = gen_keys(PARAM_MESSAGE_1_CARRY_1_KS_PBS);
    /// let (ck2, sk2) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// // Generate the server key:
    /// let ksk = KeySwitchingKey::new(
    ///     (&ck1, Some(&sk1)),
    ///     (&ck2, &sk2),
    ///     PARAM_KEYSWITCH_1_1_KS_PBS_TO_2_2_KS_PBS,
    /// );
    ///
    /// let cleartext = 1;
    ///
    /// let cipher = ck1.encrypt(cleartext);
    /// let cipher_2 = ksk.cast(&cipher);
    ///
    /// assert_eq!(ck2.decrypt(&cipher_2), cleartext);
    /// ```
    pub fn cast(&self, input_ct: &Ciphertext) -> Ciphertext {
        self.as_view().cast(input_ct)
    }
}

impl<'keys> KeySwitchingKeyView<'keys> {
    /// Deconstruct a [`KeySwitchingKeyView`] into its constituents.
    pub fn into_raw_parts(
        self,
    ) -> (
        KeySwitchingKeyMaterialView<'keys>,
        &'keys ServerKey,
        Option<&'keys ServerKey>,
    ) {
        let Self {
            key_switching_key_material,
            dest_server_key,
            src_server_key,
        } = self;

        (key_switching_key_material, dest_server_key, src_server_key)
    }

    /// Construct a [`KeySwitchingKeyView`] from its constituents.
    ///
    /// # Panics
    ///
    /// Panics if the provided raw parts are not compatible with each other, i.e.:
    ///
    /// if the provided source [`ServerKey`] ciphertext
    /// [`LweDimension`](`crate::core_crypto::commons::parameters::LweDimension`) does not match the
    /// input [`LweDimension`](`crate::core_crypto::commons::parameters::LweDimension`) of the
    /// [`LweKeyswitchKeyOwned`] in the provided [`KeySwitchingKeyMaterial`] or if the provided
    /// destination [`ServerKey`] ciphertext
    /// [`LweDimension`](`crate::core_crypto::commons::parameters::LweDimension`) does not match
    /// the output [`LweDimension`](`crate::core_crypto::commons::parameters::LweDimension`) of
    /// the [`LweKeyswitchKeyOwned`] in the provided [`KeySwitchingKeyMaterial`].
    pub fn from_raw_parts(
        key_switching_key_material: KeySwitchingKeyMaterialView<'keys>,
        dest_server_key: &'keys ServerKey,
        src_server_key: Option<&'keys ServerKey>,
    ) -> Self {
        match src_server_key {
            Some(src_server_key) => {
                let src_lwe_dimension = src_server_key.ciphertext_lwe_dimension();

                assert_eq!(
                    src_lwe_dimension,
                    key_switching_key_material
                        .key_switching_key
                        .input_key_lwe_dimension(),
                    "Mismatch between the source ServerKey ciphertext LweDimension ({:?}) \
                    and the LweKeyswitchKey input LweDimension ({:?})",
                    src_lwe_dimension,
                    key_switching_key_material
                        .key_switching_key
                        .input_key_lwe_dimension(),
                );

                assert_eq!(
                    src_server_key.ciphertext_modulus, dest_server_key.ciphertext_modulus,
                    "Mismatch between the source ServerKey CiphertextModulus ({:?}) \
                    and the destination ServerKey CiphertextModulus ({:?})",
                    src_server_key.ciphertext_modulus, dest_server_key.ciphertext_modulus,
                );
            }
            None => assert!(
                key_switching_key_material.cast_rshift >= 0,
                "Trying to build a shortint::KeySwitchingKey with a negative cast_rshift \
                without providing a source ServerKey, this is not supported"
            ),
        }

        let dst_lwe_dimension = match key_switching_key_material.destination_key {
            EncryptionKeyChoice::Big => dest_server_key.bootstrapping_key.output_lwe_dimension(),
            EncryptionKeyChoice::Small => dest_server_key.bootstrapping_key.input_lwe_dimension(),
        };

        assert_eq!(
            dst_lwe_dimension,
            key_switching_key_material
                .key_switching_key
                .output_key_lwe_dimension(),
            "Mismatch between the destination ServerKey ciphertext LweDimension ({:?}) \
            and the LweKeyswitchKey output LweDimension ({:?})",
            dst_lwe_dimension,
            key_switching_key_material
                .key_switching_key
                .output_key_lwe_dimension(),
        );
        assert_eq!(
            key_switching_key_material
                .key_switching_key
                .ciphertext_modulus(),
            dest_server_key.ciphertext_modulus,
            "Mismatch between the LweKeyswitchKey CiphertextModulus ({:?}) \
            and the destination ServerKey CiphertextModulus ({:?})",
            key_switching_key_material
                .key_switching_key
                .ciphertext_modulus(),
            dest_server_key.ciphertext_modulus,
        );

        Self {
            key_switching_key_material,
            dest_server_key,
            src_server_key,
        }
    }

    /// Cast a ciphertext from the source parameter set to the dest parameter set,
    /// returning a new ciphertext.
    ///
    /// # Example (the following code won't actually run because this function is private)
    ///
    /// ```rust
    /// use tfhe::shortint::parameters::{
    ///     PARAM_MESSAGE_1_CARRY_1_KS_PBS, PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    /// };
    /// use tfhe::shortint::prelude::*;
    /// use tfhe::shortint::{gen_keys, KeySwitchingKey};
    ///
    /// // Generate the client keys and server keys:
    /// let (ck1, sk1) = gen_keys(PARAM_MESSAGE_1_CARRY_1_KS_PBS);
    /// let (ck2, sk2) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    ///
    /// // Generate the server key:
    /// let ksk = KeySwitchingKey::new(
    ///     (&ck1, Some(&sk1)),
    ///     (&ck2, &sk2),
    ///     PARAM_KEYSWITCH_1_1_KS_PBS_TO_2_2_KS_PBS,
    /// );
    ///
    /// let cleartext = 1;
    ///
    /// let cipher = ck1.encrypt(cleartext);
    /// let cipher_2 = ksk.cast(&cipher);
    ///
    /// assert_eq!(ck2.decrypt(&cipher_2), cleartext);
    /// ```
    pub fn cast(&self, input_ct: &Ciphertext) -> Ciphertext {
        let output_lwe_size = match self.key_switching_key_material.destination_key {
            EncryptionKeyChoice::Big => self
                .dest_server_key
                .bootstrapping_key
                .output_lwe_dimension()
                .to_lwe_size(),
            EncryptionKeyChoice::Small => self
                .dest_server_key
                .bootstrapping_key
                .input_lwe_dimension()
                .to_lwe_size(),
        };
        let mut keyswitched = self
            .dest_server_key
            .unchecked_create_trivial_with_lwe_size(0, output_lwe_size);

        let cast_rshift = self.key_switching_key_material.cast_rshift;

        match cast_rshift.cmp(&0) {
            // Same bit size: only key switch
            Ordering::Equal => {
                keyswitch_lwe_ciphertext(
                    self.key_switching_key_material.key_switching_key,
                    &input_ct.ct,
                    &mut keyswitched.ct,
                );
                keyswitched.degree = input_ct.degree;
                // We don't really know where we stand in terms of noise here
                keyswitched.set_noise_level(NoiseLevel::UNKNOWN);
            }
            // Cast to bigger bit length: keyswitch, then right shift
            Ordering::Greater => {
                keyswitch_lwe_ciphertext(
                    self.key_switching_key_material.key_switching_key,
                    &input_ct.ct,
                    &mut keyswitched.ct,
                );

                let acc = self
                    .dest_server_key
                    .generate_lookup_table(|n| n >> cast_rshift);
                self.dest_server_key
                    .apply_lookup_table_assign(&mut keyswitched, &acc);
                // degree updated by the apply lookup table
                keyswitched.set_noise_level(NoiseLevel::NOMINAL);
            }
            // Cast to smaller bit length: left shift, then keyswitch
            Ordering::Less => {
                let src_server_key = self.src_server_key.as_ref().expect(
                    "No source server key in shortint::KeySwitchingKey \
                    which is required when casting to a smaller message modulus",
                );
                // We want to avoid the padding bit to be dirty, hence the modulus
                let acc = src_server_key.generate_lookup_table(|n| {
                    (n << -cast_rshift)
                        % (input_ct.carry_modulus.0 * input_ct.message_modulus.0) as u64
                });
                let shifted_cipher = src_server_key.apply_lookup_table(input_ct, &acc);

                keyswitch_lwe_ciphertext(
                    self.key_switching_key_material.key_switching_key,
                    &shifted_cipher.ct,
                    &mut keyswitched.ct,
                );
                // The degree is high in the source plaintext modulus, but smaller in the arriving
                // one.
                //
                // src 4 bits:
                // 0 | XX | 11
                // shifted:
                // 0 | 11 | 00 -> Applied lut will have max degree 1100 = 12
                // dst 2 bits :
                // 0 | 11 -> 11 = 3
                keyswitched.degree = Degree::new(shifted_cipher.degree.get() >> -cast_rshift);
                // We don't really know where we stand in terms of noise here
                keyswitched.set_noise_level(NoiseLevel::UNKNOWN);
            }
        }

        let ret = {
            let destination_pbs_order: PBSOrder =
                self.key_switching_key_material.destination_key.into();
            if destination_pbs_order == self.dest_server_key.pbs_order {
                keyswitched
            } else {
                let wrong_key_ct = keyswitched;
                let mut output = self.dest_server_key.create_trivial(0);
                output.degree = wrong_key_ct.degree;
                output.set_noise_level(wrong_key_ct.noise_level());

                // We are arriving under the wrong key for the dest_server_key
                match self.key_switching_key_material.destination_key {
                    // Big to Small == keyswitch
                    EncryptionKeyChoice::Big => {
                        keyswitch_lwe_ciphertext(
                            &self.dest_server_key.key_switching_key,
                            &wrong_key_ct.ct,
                            &mut output.ct,
                        );
                        // TODO refresh ?
                    }
                    // Small to Big == PBS
                    EncryptionKeyChoice::Small => {
                        ShortintEngine::with_thread_local_mut(|engine| {
                            let acc = self.dest_server_key.generate_lookup_table(|x| x);
                            let (_, buffers) = engine.get_buffers(self.dest_server_key);
                            apply_programmable_bootstrap(
                                &self.dest_server_key.bootstrapping_key,
                                &wrong_key_ct.ct,
                                &mut output.ct,
                                &acc.acc,
                                buffers,
                            );
                        });
                        output.set_noise_level(NoiseLevel::NOMINAL);
                    }
                }

                output
            }
        };

        ret
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(CompressedKeySwitchingKeyMaterialVersions)]
pub struct CompressedKeySwitchingKeyMaterial {
    pub(crate) key_switching_key: SeededLweKeyswitchKeyOwned<u64>,
    pub(crate) cast_rshift: i8,
    pub(crate) destination_key: EncryptionKeyChoice,
}

impl CompressedKeySwitchingKeyMaterial {
    pub fn decompress(&self) -> KeySwitchingKeyMaterial {
        let key_switching_key = {
            let cksk = &self.key_switching_key;
            let mut decompressed_ksk = LweKeyswitchKeyOwned::new(
                0u64,
                cksk.decomposition_base_log(),
                cksk.decomposition_level_count(),
                cksk.input_key_lwe_dimension(),
                cksk.output_key_lwe_dimension(),
                cksk.ciphertext_modulus(),
            );
            decompress_seeded_lwe_keyswitch_key::<_, _, _, ActivatedRandomGenerator>(
                &mut decompressed_ksk,
                cksk,
            );
            decompressed_ksk
        };

        KeySwitchingKeyMaterial {
            key_switching_key,
            cast_rshift: self.cast_rshift,
            destination_key: self.destination_key,
        }
    }
}

// This is used to have the ability to build a keyswitching key without owning the ServerKey
// It is a bit of a hack, but at this point it seems ok
pub(crate) struct CompressedKeySwitchingKeyBuildHelper<'keys> {
    pub(crate) key_switching_key_material: CompressedKeySwitchingKeyMaterial,
    pub(crate) dest_server_key: &'keys CompressedServerKey,
    pub(crate) src_server_key: Option<&'keys CompressedServerKey>,
}

/// A structure containing the casting public key.
///
/// The casting key is generated by the client and is meant to be published: the client
/// sends it to the server so it can cast from one set of parameters to another.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompressedKeySwitchingKey {
    pub(crate) key_switching_key_material: CompressedKeySwitchingKeyMaterial,
    pub(crate) dest_server_key: CompressedServerKey,
    pub(crate) src_server_key: Option<CompressedServerKey>,
}

impl<'keys> From<CompressedKeySwitchingKeyBuildHelper<'keys>> for CompressedKeySwitchingKey {
    fn from(value: CompressedKeySwitchingKeyBuildHelper) -> Self {
        let CompressedKeySwitchingKeyBuildHelper {
            key_switching_key_material,
            dest_server_key,
            src_server_key,
        } = value;

        Self {
            key_switching_key_material,
            dest_server_key: dest_server_key.to_owned(),
            src_server_key: src_server_key.map(ToOwned::to_owned),
        }
    }
}

impl<'keys> CompressedKeySwitchingKeyBuildHelper<'keys> {
    pub(crate) fn new<'input_key, InputEncryptionKey>(
        input_key_pair: (InputEncryptionKey, Option<&'keys CompressedServerKey>),
        output_key_pair: (&'keys ClientKey, &'keys CompressedServerKey),
        params: ShortintKeySwitchingParameters,
    ) -> Self
    where
        InputEncryptionKey: Into<SecretEncryptionKeyView<'input_key>>,
    {
        let input_secret_key: SecretEncryptionKeyView<'_> = input_key_pair.0.into();

        // Creation of the key switching key
        let key_switching_key = ShortintEngine::with_thread_local_mut(|engine| {
            engine.new_seeded_key_switching_key(&input_secret_key, output_key_pair.0, params)
        });

        let full_message_modulus_input =
            input_secret_key.carry_modulus.0 * input_secret_key.message_modulus.0;
        let full_message_modulus_output = output_key_pair.0.parameters.carry_modulus().0
            * output_key_pair.0.parameters.message_modulus().0;
        assert!(
            full_message_modulus_input.is_power_of_two()
                && full_message_modulus_output.is_power_of_two(),
            "Cannot create casting key if the full messages moduli are not a power of 2"
        );
        if full_message_modulus_input > full_message_modulus_output {
            assert!(
                input_key_pair.1.is_some(),
                "Trying to build a shortint::KeySwitchingKey \
                going from a large modulus {full_message_modulus_input} \
                to a smaller modulus {full_message_modulus_output} \
                without providing a source ServerKey, this is not supported"
            );
        }

        let nb_bits_input: i8 = full_message_modulus_input.ilog2().try_into().unwrap();
        let nb_bits_output: i8 = full_message_modulus_output.ilog2().try_into().unwrap();

        // Pack the keys in the casting key set:
        Self {
            key_switching_key_material: CompressedKeySwitchingKeyMaterial {
                key_switching_key,
                cast_rshift: nb_bits_output - nb_bits_input,
                destination_key: params.destination_key,
            },
            dest_server_key: output_key_pair.1,
            src_server_key: input_key_pair.1,
        }
    }
}

impl CompressedKeySwitchingKey {
    pub fn new<'input_key, InputEncryptionKey>(
        input_key_pair: (InputEncryptionKey, Option<&CompressedServerKey>),
        output_key_pair: (&ClientKey, &CompressedServerKey),
        params: ShortintKeySwitchingParameters,
    ) -> Self
    where
        InputEncryptionKey: Into<SecretEncryptionKeyView<'input_key>>,
    {
        CompressedKeySwitchingKeyBuildHelper::new(input_key_pair, output_key_pair, params).into()
    }

    pub fn decompress(&self) -> KeySwitchingKey {
        KeySwitchingKey {
            key_switching_key_material: self.key_switching_key_material.decompress(),
            dest_server_key: self.dest_server_key.decompress(),
            src_server_key: self
                .src_server_key
                .as_ref()
                .map(CompressedServerKey::decompress),
        }
    }
}
