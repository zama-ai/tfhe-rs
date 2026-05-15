//! Fast TFHE implementation of the Kreyvium algorithm following the
//! "Computation of the Kreyvium Loop" note: each round packs the XOR-and-AND
//! into a linear expression over Z_4 and extracts the result with a single
//! constant-LUT PBS (BitExt). The register state is encoded natively at
//! Δ = q/4, avoiding the noise penalty of a per-round promote-by-4.

use crate::core_crypto::prelude::{
    allocate_and_encrypt_new_lwe_ciphertext, allocate_and_trivially_encrypt_new_lwe_ciphertext,
    keyswitch_lwe_ciphertext, lwe_ciphertext_add_assign, lwe_ciphertext_cleartext_mul_assign,
    Cleartext, ComputationBuffers, GlweCiphertextOwned, GlweSize, LweCiphertextOwned, Plaintext,
    PolynomialSize,
};
use crate::shortint::atomic_pattern::{AtomicPattern, AtomicPatternServerKey};
use crate::shortint::ciphertext::{Degree, NoiseLevel};
use crate::shortint::engine::ShortintEngine;
use crate::shortint::server_key::{apply_programmable_bootstrap, ShortintBootstrappingKey};
use crate::shortint::{CiphertextModulus, Ciphertext, ClientKey, ServerKey};
use crate::transciphering::ciphers::shift_register::ShiftRegister;
use crate::transciphering::{Transcipherer, TranscipheringCipherKind};

use super::{KreyviumRound, KreyviumRoundInput, KreyviumRoundOutput, KreyviumState, KreyviumStream};

/// One Kreyvium register bit on the fast pipeline: a raw LWE on the big
/// (post-PBS) key, encoding `m ∈ {0,1}` at Δ = q/4 (body holds
/// `m · (1u64 << 62)` + noise).
pub type FastBit = LweCiphertextOwned<u64>;

// Δ for register-resident bits = q/4 → log2(Δ/2) = 61.
const DELTA_HALF_INTERNAL: u64 = 1u64 << 61;
// Δ for keystream bits: matches shortint 2_2's `delta = q / (2·msg·carry) = q/32`,
// so Δ/2 = q/64 = 1<<58.
const DELTA_HALF_EXTERNAL: u64 = 1u64 << 58;

/// 128 encrypted symmetric-key bits, pre-encoded at Δ = q/4 by the client.
pub struct KreyviumFastEncryptedKey {
    pub cts: [FastBit; 128],
}

impl From<[FastBit; 128]> for KreyviumFastEncryptedKey {
    fn from(cts: [FastBit; 128]) -> Self {
        Self { cts }
    }
}

pub type KreyviumFastFheStream = KreyviumStream<FastBit>;

impl KreyviumFastFheStream {
    pub fn new(key: KreyviumFastEncryptedKey, iv: [u64; 128], sk: &ServerKey) -> Self {
        let mut state = KreyviumFastFheState::new(key, iv, sk);
        state.warmup(sk);
        state.counter = 0;
        Self { state }
    }
}

impl Transcipherer for KreyviumFastFheStream {
    fn kind(&self) -> TranscipheringCipherKind {
        TranscipheringCipherKind::Kreyvium
    }

    fn next_keystream_bits(&mut self, sks: &ServerKey, n_bits: usize) -> Vec<Ciphertext> {
        let raw_bits = self.state.next_n(sks, n_bits);
        raw_bits
            .into_iter()
            .map(|lwe| wrap_fast_bit(lwe, sks))
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
        let mut key = key.cts;

        let mut a_register: [FastBit; 93] = std::array::from_fn(|_| trivial_fast_bit(0, sk));
        let mut b_register: [FastBit; 84] = std::array::from_fn(|_| trivial_fast_bit(0, sk));
        let mut c_register: [FastBit; 111] = std::array::from_fn(|_| trivial_fast_bit(0, sk));

        for i in 0..93 {
            a_register[i] = key[128 - 93 + i].clone();
        }
        for i in 0..84 {
            b_register[i] = trivial_fast_bit(iv[128 - 84 + i], sk);
        }
        for i in 0..44 {
            c_register[111 - 44 + i] = trivial_fast_bit(iv[i], sk);
        }
        for i in 0..66 {
            c_register[i + 1] = trivial_fast_bit(1, sk);
        }

        key.reverse();
        iv.reverse();
        let iv_cts: [FastBit; 128] = iv.map(|x| trivial_fast_bit(x, sk));

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
        let ap = match &sk.atomic_pattern {
            AtomicPatternServerKey::Standard(ap) => ap,
            _ => panic!(
                "KreyviumFastFheStream requires the Standard atomic pattern (got {:?})",
                sk.atomic_pattern.kind()
            ),
        };
        let bsk = &ap.bootstrapping_key;
        let ksk = &ap.key_switching_key;
        let modulus = sk.atomic_pattern.ciphertext_modulus();
        let glwe_size = bsk.glwe_size();
        let poly_size = bsk.polynomial_size();

        let lut_internal = build_constant_lut(glwe_size, poly_size, modulus, DELTA_HALF_INTERNAL);
        let lut_external = build_constant_lut(glwe_size, poly_size, modulus, DELTA_HALF_EXTERNAL);

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
        let acc_t1 = build_accumulator(&[a1, a2, b5, iv], &[a3, a4]);
        let acc_t2 = build_accumulator(&[b1, b2, c5], &[b3, b4]);
        let acc_t3 = build_accumulator(&[c1, c2, k, a5], &[c3, c4]);
        let acc_r = build_accumulator(&[a1, a2, b1, b2, c1, c2, k], &[]);

        let ((b_out, c_out), (a_out, r_out)) = rayon::join(
            || {
                rayon::join(
                    || bit_ext(bsk, ksk, &lut_internal, DELTA_HALF_INTERNAL, acc_t1),
                    || bit_ext(bsk, ksk, &lut_internal, DELTA_HALF_INTERNAL, acc_t2),
                )
            },
            || {
                rayon::join(
                    || bit_ext(bsk, ksk, &lut_internal, DELTA_HALF_INTERNAL, acc_t3),
                    || bit_ext(bsk, ksk, &lut_external, DELTA_HALF_EXTERNAL, acc_r),
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

/// Client-side helper: encrypt a single bit at Δ = q/4 under the same LWE
/// secret key + noise distribution that `client_key.encrypt(_)` would use.
/// Returns a `FastBit` directly consumable by `KreyviumFastEncryptedKey`.
pub fn encrypt_fast_bit(client_key: &ClientKey, bit: u64) -> FastBit {
    ShortintEngine::with_thread_local_mut(|engine| {
        let (lwe_sk, noise) = client_key.encryption_key_and_noise();
        let modulus = client_key.parameters().ciphertext_modulus();
        let plaintext = Plaintext(bit.wrapping_mul(DELTA_HALF_INTERNAL << 1));
        allocate_and_encrypt_new_lwe_ciphertext(
            &lwe_sk,
            plaintext,
            noise,
            modulus,
            &mut engine.encryption_generator,
        )
    })
}

fn trivial_fast_bit(bit: u64, sk: &ServerKey) -> FastBit {
    let lwe_size = sk.atomic_pattern.ciphertext_lwe_dimension().to_lwe_size();
    let modulus = sk.atomic_pattern.ciphertext_modulus();
    let plaintext = Plaintext(bit.wrapping_mul(DELTA_HALF_INTERNAL << 1));
    allocate_and_trivially_encrypt_new_lwe_ciphertext(lwe_size, plaintext, modulus)
}

fn wrap_fast_bit(lwe: FastBit, sks: &ServerKey) -> Ciphertext {
    Ciphertext::new(
        lwe,
        Degree::new(1),
        NoiseLevel::NOMINAL,
        sks.message_modulus,
        sks.carry_modulus,
        sks.atomic_pattern.kind(),
    )
}

/// Trivial GLWE accumulator whose body coefficients are all `-delta_out_half`.
/// Combined with negacyclic PBS lookup + `+delta_out_half` recenter this maps
/// the bit at position q/2 of the input to a clean encryption at Δ = 2·delta_out_half.
fn build_constant_lut(
    glwe_size: GlweSize,
    poly_size: PolynomialSize,
    modulus: CiphertextModulus,
    delta_out_half: u64,
) -> GlweCiphertextOwned<u64> {
    let mut acc = GlweCiphertextOwned::new(0u64, glwe_size, poly_size, modulus);
    let body_value = delta_out_half.wrapping_neg();
    for coeff in acc.get_mut_body().as_mut().iter_mut() {
        *coeff = body_value;
    }
    acc
}

/// Build `2·(Σ xor_terms) + Σ and_terms` (mod q) as a single LWE at Δ = q/4.
/// `xor_terms` must be non-empty.
fn build_accumulator(xor_terms: &[&FastBit], and_terms: &[&FastBit]) -> FastBit {
    let (head, tail) = xor_terms.split_first().expect("xor_terms must be non-empty");
    let mut acc = (*head).clone();
    for term in tail {
        lwe_ciphertext_add_assign(&mut acc, *term);
    }
    lwe_ciphertext_cleartext_mul_assign(&mut acc, Cleartext(2u64));
    for term in and_terms {
        lwe_ciphertext_add_assign(&mut acc, *term);
    }
    acc
}

/// PDF Algorithm 1: center input by Δ_in/2 = q/8, keyswitch to small key,
/// PBS with the given constant LUT, recenter output by Δ_out/2.
fn bit_ext(
    bsk: &ShortintBootstrappingKey<u64>,
    ksk: &crate::core_crypto::prelude::LweKeyswitchKeyOwned<u64>,
    lut: &GlweCiphertextOwned<u64>,
    delta_out_half: u64,
    mut acc: FastBit,
) -> FastBit {
    let modulus = acc.ciphertext_modulus();

    // 1. Center input by Δ_in/2 = q/8 (Δ_in = q/4, fixed by the register encoding).
    *acc.get_mut_body().data = acc.get_body().data.wrapping_add(DELTA_HALF_INTERNAL);

    // 2. KS big → small.
    let mut ks_out = LweCiphertextOwned::new(0u64, ksk.output_lwe_size(), modulus);
    keyswitch_lwe_ciphertext(ksk, &acc, &mut ks_out);

    // 3. PBS small → big with the constant LUT.
    let mut pbs_out = LweCiphertextOwned::new(
        0u64,
        bsk.output_lwe_dimension().to_lwe_size(),
        modulus,
    );
    let mut buffers = ComputationBuffers::new();
    apply_programmable_bootstrap(bsk, &ks_out, &mut pbs_out, lut, &mut buffers);

    // 4. Recenter output by Δ_out/2.
    *pbs_out.get_mut_body().data = pbs_out.get_body().data.wrapping_add(delta_out_half);

    pbs_out
}
