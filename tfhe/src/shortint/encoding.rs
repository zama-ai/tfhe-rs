use crate::core_crypto::algorithms::misc::divide_round;
use crate::core_crypto::entities::{Cleartext, Plaintext};
use crate::core_crypto::prelude::{CastFrom, CastInto, CiphertextModulusKind, UnsignedInteger};
use crate::shortint::parameters::CoreCiphertextModulus;
use crate::shortint::{CarryModulus, MessageModulus, ShortintParameterSet};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum PaddingBit {
    No = 0,
    Yes = 1,
}

pub(crate) fn compute_delta<Scalar: UnsignedInteger + CastFrom<u64>>(
    ciphertext_modulus: CoreCiphertextModulus<Scalar>,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    padding_bit: PaddingBit,
) -> Scalar {
    let cleartext_modulus = Scalar::cast_from(carry_modulus.0 * message_modulus.0);

    match ciphertext_modulus.kind() {
        CiphertextModulusKind::Native => {
            (Scalar::ONE << (Scalar::BITS - 1 - padding_bit as usize)) / cleartext_modulus
                * Scalar::TWO
        }
        CiphertextModulusKind::Other | CiphertextModulusKind::NonNativePowerOfTwo => {
            let custom_modulus: Scalar = ciphertext_modulus.get_custom_modulus().cast_into();
            custom_modulus
                / cleartext_modulus
                / if padding_bit == PaddingBit::Yes {
                    Scalar::TWO
                } else {
                    Scalar::ONE
                }
        }
    }
}

pub(crate) struct ShortintEncoding<Scalar: UnsignedInteger> {
    pub(crate) ciphertext_modulus: CoreCiphertextModulus<Scalar>,
    pub(crate) message_modulus: MessageModulus,
    pub(crate) carry_modulus: CarryModulus,
    pub(crate) padding_bit: PaddingBit,
}

impl<Scalar: UnsignedInteger + CastFrom<u64>> ShortintEncoding<Scalar> {
    pub(crate) fn delta(&self) -> Scalar {
        compute_delta(
            self.ciphertext_modulus,
            self.message_modulus,
            self.carry_modulus,
            self.padding_bit,
        )
    }
}

impl<Scalar: UnsignedInteger + CastFrom<u64>> ShortintEncoding<Scalar> {
    /// Return the cleatext space including the space for the [`Self::padding_bit`] if it is set to
    /// [`PaddingBit::Yes`].
    pub(crate) fn full_cleartext_space(&self) -> Scalar {
        let cleartext_modulus = self.cleartext_space_without_padding();

        cleartext_modulus
            * if self.padding_bit == PaddingBit::No {
                Scalar::ONE
            } else {
                Scalar::TWO
            }
    }

    /// Return the cleatext space defined by the [`Self::message_modulus`] and
    /// [`Self::carry_modulus`], not taking the value of the [`Self::padding_bit`] into account.
    pub(crate) fn cleartext_space_without_padding(&self) -> Scalar {
        (self.message_modulus.0 * self.carry_modulus.0).cast_into()
    }

    pub(crate) fn encode(&self, value: Cleartext<Scalar>) -> Plaintext<Scalar> {
        let delta = compute_delta(
            self.ciphertext_modulus,
            self.message_modulus,
            self.carry_modulus,
            self.padding_bit,
        );

        Plaintext(value.0.wrapping_mul(delta))
    }

    pub(crate) fn decode(&self, value: Plaintext<Scalar>) -> Cleartext<Scalar> {
        assert!(self.ciphertext_modulus.is_compatible_with_native_modulus());
        let delta = self.delta();

        // Force the decoded value to be in the correct range
        Cleartext(divide_round(value.0, delta) % self.full_cleartext_space())
    }
}

impl ShortintEncoding<u64> {
    pub(crate) fn from_parameters(
        params: impl Into<ShortintParameterSet>,
        padding_bit: PaddingBit,
    ) -> Self {
        let params = params.into();
        Self {
            ciphertext_modulus: params.ciphertext_modulus(),
            message_modulus: params.message_modulus(),
            carry_modulus: params.carry_modulus(),
            padding_bit,
        }
    }
}

#[test]
fn test_pow_2_encoding_ci_run_filter() {
    use crate::shortint::parameters::test_params::TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    use crate::shortint::parameters::CiphertextModulus;
    const CIPHERTEXT_MODULUS: u64 = 1u64 << 62;

    let mut params = TEST_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M128;
    params.carry_modulus = CarryModulus(1);
    params.ciphertext_modulus = CiphertextModulus::new(CIPHERTEXT_MODULUS as u128);

    let encoding = ShortintEncoding::from_parameters(params, PaddingBit::Yes);
    let (cks, _sks) = crate::shortint::gen_keys(params);
    for m in 0..params.message_modulus.0 {
        let encoded = encoding.encode(Cleartext(m));
        assert!(
            encoded.0 < (CIPHERTEXT_MODULUS / 2),
            "encoded message goes beyond its allowed space"
        );

        let ct = cks.encrypt(m);

        let decrypted = cks.decrypt(&ct);
        assert_eq!(decrypted, m);
    }
}
