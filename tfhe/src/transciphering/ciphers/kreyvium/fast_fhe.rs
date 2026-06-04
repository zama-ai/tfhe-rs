//! Fast TFHE implementation of the Kreyvium algorithm following the
//! "Computation of the Kreyvium Loop" note: each round packs the XOR-and-AND
//! into a linear expression over Z_4 and extracts the result with a single
//! constant-LUT PBS (BitExt). Register bits are plain shortint ciphertexts
//! under 1-bit parameters (1 bit of message + 1 bit of padding, Δ = q/4), so
//! the linear phase runs on shortint primitives with noise-level tracking.

use crate::core_crypto::prelude::GlweCiphertextOwned;
use crate::shortint::atomic_pattern::AtomicPattern;
use crate::shortint::ciphertext::Degree;
use crate::shortint::parameters::{
    CarryModulus, CiphertextModulus32, DecompositionBaseLog, DecompositionLevelCount,
    DynamicDistribution, GlweDimension, KeySwitch32PBSParameters, LweDimension, MaxNoiseLevel,
    MessageModulus, ModulusSwitchType, PolynomialSize,
};
use crate::shortint::server_key::LookupTableOwned;
use crate::shortint::{Ciphertext, CiphertextModulus, ServerKey};
use crate::transciphering::ciphers::shift_register::ShiftRegister;
use crate::transciphering::{Transcipherer, TranscipheringCipherKind};

use super::{
    KreyviumRound, KreyviumRoundInput, KreyviumRoundOutput, KreyviumState, KreyviumStream,
};

/// One Kreyvium register bit on the fast pipeline: a shortint ciphertext
/// under 1-bit parameters, encoding `m ∈ {0,1}` at Δ = q/4. Newtype so the
/// fast `KreyviumStream`/`KreyviumRound` impls don't collide with the
/// standard shortint ones in `fhe.rs`.
#[derive(Clone)]
pub struct FastBit(pub Ciphertext);

/// Dedicated parameter set for the fast Kreyvium pipeline (from
/// `kreyvium_params.json`): KS32 atomic pattern, TUniform noise, 132-bit
/// security, p-fail = 2^-128.992. Encodes 1 bit of message with 1 bit of
/// padding (Δ = q/4), matching the pipeline's native register encoding.
pub const PARAM_KREYVIUM_1_0_KS32_TUNIFORM_2M128: KeySwitch32PBSParameters =
    KeySwitch32PBSParameters {
        lwe_dimension: LweDimension(720),
        glwe_dimension: GlweDimension(5),
        polynomial_size: PolynomialSize(256),
        lwe_noise_distribution: DynamicDistribution::new_t_uniform(18),
        glwe_noise_distribution: DynamicDistribution::new_t_uniform(36),
        pbs_base_log: DecompositionBaseLog(9),
        pbs_level: DecompositionLevelCount(2),
        ks_base_log: DecompositionBaseLog(2),
        ks_level: DecompositionLevelCount(6),
        message_modulus: MessageModulus(2),
        carry_modulus: CarryModulus(1),
        // The round's worst multisum is `2·(7 register bits)` → tracked noise
        // level 14 (shortint tracks the multisum 2-norm linearly via the
        // triangle inequality; the actual 2-norm covered by the noise
        // analysis is √28).
        max_noise_level: MaxNoiseLevel::new(14),
        log2_p_fail: -128.992,
        post_keyswitch_ciphertext_modulus: CiphertextModulus32::new_native(),
        ciphertext_modulus: CiphertextModulus::new_native(),
        modulus_switch_noise_reduction_params: ModulusSwitchType::CenteredMeanNoiseReduction,
    };

// Δ/2 = q/8 for the 1-bit encoding (Δ = q/4).
const DELTA_HALF: u64 = 1u64 << 61;

/// 128 encrypted symmetric-key bits: shortint encryptions of `{0,1}` under
/// the pipeline's 1-bit parameters.
pub struct KreyviumFastEncryptedKey {
    pub cts: [FastBit; 128],
}

impl From<[Ciphertext; 128]> for KreyviumFastEncryptedKey {
    fn from(cts: [Ciphertext; 128]) -> Self {
        Self {
            cts: cts.map(FastBit),
        }
    }
}

pub type KreyviumFastFheStream = KreyviumStream<FastBit>;

impl KreyviumFastFheStream {
    pub fn new(key: KreyviumFastEncryptedKey, iv: [u64; 128], sk: &ServerKey) -> Self {
        let mut state = KreyviumFastFheState::new(key, iv, sk);
        state.warmup(sk);

        Self { state }
    }
}

impl Transcipherer for KreyviumFastFheStream {
    fn kind(&self) -> TranscipheringCipherKind {
        TranscipheringCipherKind::Kreyvium
    }

    fn next_keystream_bits(&mut self, sks: &ServerKey, n_bits: usize) -> Vec<Ciphertext> {
        self.state
            .next_n(sks, n_bits)
            .into_iter()
            .map(|bit| bit.0)
            .collect()
    }

    fn skip(&mut self, sks: &ServerKey, n_bits: usize) {
        self.state.next_n(sks, n_bits);
    }

    fn current_counter(&self) -> u64 {
        self.state.counter
    }
}

type KreyviumFastFheState = KreyviumState<FastBit>;

impl KreyviumFastFheState {
    pub fn new(key: KreyviumFastEncryptedKey, mut iv: [u64; 128], sk: &ServerKey) -> Self {
        assert_eq!(
            sk.message_modulus.0 * sk.carry_modulus.0,
            2,
            "KreyviumFastFheStream requires parameters encoding 1 bit of message with 1 bit of \
            padding, such as PARAM_KREYVIUM_1_0_KS32_TUNIFORM_2M128 (got message modulus {}, \
            carry modulus {})",
            sk.message_modulus.0,
            sk.carry_modulus.0,
        );

        let mut key = key.cts;

        let trivial = |bit: u64| FastBit(sk.create_trivial(bit));

        let mut a_register: [FastBit; 93] = std::array::from_fn(|_| trivial(0));
        let mut b_register: [FastBit; 84] = std::array::from_fn(|_| trivial(0));
        let mut c_register: [FastBit; 111] = std::array::from_fn(|_| trivial(0));

        for i in 0..93 {
            a_register[i] = key[128 - 93 + i].clone();
        }
        for i in 0..84 {
            b_register[i] = trivial(iv[128 - 84 + i]);
        }
        for i in 0..44 {
            c_register[111 - 44 + i] = trivial(iv[i]);
        }
        for i in 0..66 {
            c_register[i + 1] = trivial(1);
        }

        key.reverse();
        iv.reverse();
        let iv_cts: [FastBit; 128] = iv.map(trivial);

        Self {
            a: ShiftRegister::new(a_register),
            b: ShiftRegister::new(b_register),
            c: ShiftRegister::new(c_register),
            k: ShiftRegister::new(key),
            iv: ShiftRegister::new(iv_cts),
            counter: 0,
        }
    }
}

type KreyviumFastFheRoundInput<'a> = KreyviumRoundInput<'a, FastBit>;

impl KreyviumRound for KreyviumFastFheRoundInput<'_> {
    type AuxData = ServerKey;
    type Bit = FastBit;

    fn round(self, sk: &Self::AuxData) -> KreyviumRoundOutput<Self::Bit> {
        let lut = build_bit_ext_lut(sk);

        let KreyviumRoundInput {
            a: (a1, a2, a3, a4, a5),
            b: (b1, b2, b3, b4, b5),
            c: (c1, c2, c3, c4, c5),
            k,
            iv,
        } = self;

        // PDF round equations under our encoding (each input at Δ = q/4):
        //   t1 = BitExt( 2·(s66 + s93 + s171 + iv127) + (s91 + s92) )   → output b
        //   t2 = BitExt( 2·(s162 + s177 + s264)       + (s175 + s176) ) → output c
        //   t3 = BitExt( 2·(s243 + s288 + k127 + s69) + (s286 + s287) ) → output a
        //   r  = BitExt( 2·(s66 + s93 + s162 + s177 + s243 + s288 + k127) )
        let acc_t1 = build_accumulator(sk, &[a1, a2, b5, iv], &[a3, a4]);
        let acc_t2 = build_accumulator(sk, &[b1, b2, c5], &[b3, b4]);
        let acc_t3 = build_accumulator(sk, &[c1, c2, k, a5], &[c3, c4]);
        let acc_r = build_accumulator(sk, &[a1, a2, b1, b2, c1, c2, k], &[]);

        let ((b_out, c_out), (a_out, r_out)) = rayon::join(
            || {
                rayon::join(
                    || bit_ext(sk, &lut, acc_t1),
                    || bit_ext(sk, &lut, acc_t2),
                )
            },
            || {
                rayon::join(
                    || bit_ext(sk, &lut, acc_t3),
                    || bit_ext(sk, &lut, acc_r),
                )
            },
        );

        KreyviumRoundOutput {
            output: r_out,
            a: a_out,
            b: b_out,
            c: c_out,
        }
    }
}

/// Trivial GLWE accumulator whose body coefficients are all `-Δ/2`. Combined
/// with negacyclic PBS lookup + `+Δ/2` recenter this maps the bit at position
/// q/2 of the input to a clean encryption at Δ = q/4.
fn build_bit_ext_lut(sk: &ServerKey) -> LookupTableOwned {
    let size = sk.atomic_pattern.lookup_table_size();
    let mut acc = GlweCiphertextOwned::new(
        0u64,
        size.glwe_size(),
        size.polynomial_size(),
        sk.atomic_pattern.ciphertext_modulus(),
    );
    let body_value = DELTA_HALF.wrapping_neg();
    for coeff in acc.get_mut_body().as_mut().iter_mut() {
        *coeff = body_value;
    }
    LookupTableOwned {
        acc,
        degree: Degree::new(1),
    }
}

/// Build `2·(Σ xor_terms) + Σ and_terms` (mod q) as a single shortint
/// ciphertext at Δ = q/4. `xor_terms` must be non-empty.
///
/// The value intentionally overflows the 1-bit message space (BitExt reads it
/// through the padding bit), so the tracked degree is not meaningful; the
/// noise level however is, and the unchecked operations validate it against
/// `max_noise_level` in `noise-asserts` builds.
fn build_accumulator(sk: &ServerKey, xor_terms: &[&FastBit], and_terms: &[&FastBit]) -> Ciphertext {
    let (head, tail) = xor_terms
        .split_first()
        .expect("xor_terms must be non-empty");
    let mut acc = head.0.clone();
    for term in tail {
        sk.unchecked_add_assign(&mut acc, &term.0);
    }
    sk.unchecked_scalar_mul_assign(&mut acc, 2);
    for term in and_terms {
        sk.unchecked_add_assign(&mut acc, &term.0);
    }
    acc
}

/// PDF Algorithm 1: center input by Δ/2 = q/8, keyswitch + PBS with the
/// constant LUT, recenter output by Δ/2.
fn bit_ext(sk: &ServerKey, lut: &LookupTableOwned, mut acc: Ciphertext) -> FastBit {
    // 1. Center input by Δ/2.
    let body = acc.ct.get_mut_body().data;
    *body = body.wrapping_add(DELTA_HALF);

    // 2. KS + PBS through the atomic pattern. Called directly rather than via
    // `ServerKey::apply_lookup_table_assign`: its trivial-ciphertext shortcut
    // decodes assuming an uncentered input and would mis-round the Δ/2 offset.
    sk.atomic_pattern.apply_lookup_table_assign(&mut acc, lut);
    acc.degree = lut.degree;
    acc.set_noise_level_to_nominal();

    // 3. Recenter output by Δ/2.
    let body = acc.ct.get_mut_body().data;
    *body = body.wrapping_add(DELTA_HALF);

    FastBit(acc)
}
