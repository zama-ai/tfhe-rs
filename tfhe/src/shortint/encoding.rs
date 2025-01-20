use crate::core_crypto::entities::{Cleartext, Plaintext};
use crate::core_crypto::prelude::CiphertextModulusKind;
use crate::shortint::{CarryModulus, CiphertextModulus, MessageModulus, ShortintParameterSet};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum PaddingBit {
    No = 0,
    Yes = 1,
}

fn compute_delta(
    ciphertext_modulus: CiphertextModulus,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    padding_bit: PaddingBit,
) -> u64 {
    match ciphertext_modulus.kind() {
        CiphertextModulusKind::Native => {
            (1u64 << (u64::BITS - 1 - padding_bit as u32)) / (carry_modulus.0 * message_modulus.0)
                * 2
        }
        CiphertextModulusKind::Other | CiphertextModulusKind::NonNativePowerOfTwo => {
            ciphertext_modulus.get_custom_modulus() as u64
                / (carry_modulus.0 * message_modulus.0)
                / if padding_bit == PaddingBit::Yes { 2 } else { 1 }
        }
    }
}

pub(crate) struct ShortintEncoding {
    pub(crate) ciphertext_modulus: CiphertextModulus,
    pub(crate) message_modulus: MessageModulus,
    pub(crate) carry_modulus: CarryModulus,
    pub(crate) padding_bit: PaddingBit,
}

impl ShortintEncoding {
    pub(crate) fn delta(&self) -> u64 {
        compute_delta(
            self.ciphertext_modulus,
            self.message_modulus,
            self.carry_modulus,
            self.padding_bit,
        )
    }
}

impl ShortintEncoding {
    fn plaintext_space(&self) -> u64 {
        self.message_modulus.0
            * self.carry_modulus.0
            * if self.padding_bit == PaddingBit::No {
                1
            } else {
                2
            }
    }
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

    pub(crate) fn encode(&self, value: Cleartext<u64>) -> Plaintext<u64> {
        let delta = compute_delta(
            self.ciphertext_modulus,
            self.message_modulus,
            self.carry_modulus,
            self.padding_bit,
        );

        Plaintext(value.0.wrapping_mul(delta))
    }

    pub(crate) fn decode(&self, value: Plaintext<u64>) -> Cleartext<u64> {
        assert!(self.ciphertext_modulus.is_compatible_with_native_modulus());
        let delta = self.delta();

        // The bit before the message
        let rounding_bit = delta >> 1;

        // Compute the rounding bit
        let rounding = (value.0 & rounding_bit) << 1;

        // Force the decoded value to be in the correct range
        Cleartext((value.0.wrapping_add(rounding) / delta) % (self.plaintext_space()))
    }
}

#[test]
fn test_pow_2_encoding_ci_run_filter() {
    use crate::shortint::parameters::V0_10_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64;
    const CIPHERTEXT_MODULUS: u64 = 1u64 << 62;

    let mut params = V0_10_PARAM_MESSAGE_2_CARRY_2_KS_PBS_GAUSSIAN_2M64;
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
