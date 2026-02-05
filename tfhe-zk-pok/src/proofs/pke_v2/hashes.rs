use std::iter::successors;

use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

/// Scalar generation using the hash random oracle
use crate::{
    backward_compatibility::pke_v2::{PkeV2HashModeVersions, PkeV2SupportedHashConfigVersions},
    curve_api::{Curve, FieldOps},
    proofs::pke_v2::{compute_crs_params, inf_norm_bound_to_euclidean_squared},
};

use super::{PKEv2DomainSeparators, PublicCommit, PublicParams};

/// Generates the vector `[1, y, y^2, y^3, ...]` from y
fn generate_powers<Zp: FieldOps>(scalar: Zp, out: &mut [Zp]) {
    let powers_iterator = successors(Some(scalar), move |prev| Some(*prev * scalar));

    if let Some(val0) = out.get_mut(0) {
        *val0 = Zp::ONE;
    }

    for (val, power) in out[1..].iter_mut().zip(powers_iterator) {
        *val = power;
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Versionize)]
#[versionize(PkeV2HashModeVersions)]
/// Defines how the hash functions will be used to generate values
pub enum PkeV2HashMode {
    /// Compatibility with proofs generated with tfhe-zk-pok 0.6.0 and earlier
    BackwardCompat = 0,
    /// The basic PkeV2 scheme without the hashes optimizations
    Classical = 1,
    /// Reduce the number of hashed bytes with various optimizations:
    /// - generates only y1 as a hash and derives y = [1, y1, y1^2,...]
    /// - only hash R in phi
    Compact = 2,
}

#[derive(Debug, Clone, Copy)]
/// How the position of bits proven to be 0 is encoded
pub enum PkeV2ProvenZeroBitsEncoding {
    /// Light encoding where we only store the number of msb bits, that is the same for all slots
    MsbZeroBitsCountOnly = 0,
    /// Flexible encoding that allows to define any bit in any slot as being proven to be 0
    AnyBitAnySlot = 1,
}

impl PkeV2ProvenZeroBitsEncoding {
    pub fn encode_proven_zero_bits(
        &self,
        msb_zero_padding_bit_count: u64,
        t: u64,
        k: usize,
    ) -> Vec<u8> {
        match self {
            PkeV2ProvenZeroBitsEncoding::MsbZeroBitsCountOnly => {
                msb_zero_padding_bit_count.to_le_bytes().to_vec()
            }
            PkeV2ProvenZeroBitsEncoding::AnyBitAnySlot => {
                encode_proven_zero_bits_anybit_anyslot(msb_zero_padding_bit_count, t, k)
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
/// The kind of norm bound that is hashed in the statement.
pub enum PkeV2HashedBoundType {
    /// Hash the square of the derived L2/Euclidean norm that is used for the proof
    SquaredEuclideanNorm = 0,
    /// Hash the infinite norm given as input by the prover
    InfinityNorm = 1,
}

#[derive(Debug, Clone, Copy)]
pub struct PkeV2HashConfig {
    pub(crate) mode: PkeV2HashMode,
    pub(crate) proven_zero_bits_encoding: PkeV2ProvenZeroBitsEncoding,
    pub(crate) hashed_bound_type: PkeV2HashedBoundType,
    /// Should we also hash the value of k with the statement
    pub(crate) hash_k: bool,
}

impl PkeV2HashConfig {
    pub fn mode(&self) -> PkeV2HashMode {
        self.mode
    }

    pub fn proven_zero_bits_encoding(&self) -> PkeV2ProvenZeroBitsEncoding {
        self.proven_zero_bits_encoding
    }

    pub fn hashed_bound(&self) -> PkeV2HashedBoundType {
        self.hashed_bound_type
    }

    pub fn hash_k(&self) -> bool {
        self.hash_k
    }
}

/// List of hash config that were used for a given version of this crate
///
/// This is stored in the proof so that we only support a specific subset of all possible config.
#[derive(Default, Copy, Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(PkeV2SupportedHashConfigVersions)]
pub enum PkeV2SupportedHashConfig {
    V0_4_0 = 0,
    V0_7_0 = 1,
    // Default hashing configuration used for proofs. This can be updated for performance or
    // compliance reasons as long as we still handle the previous version for backward
    // compatibility.
    #[default]
    V0_8_0 = 2,
}

const PKEV2_HASH_CONFIG_V0_4_0: PkeV2HashConfig = PkeV2HashConfig {
    mode: PkeV2HashMode::BackwardCompat,
    proven_zero_bits_encoding: PkeV2ProvenZeroBitsEncoding::MsbZeroBitsCountOnly,
    hashed_bound_type: PkeV2HashedBoundType::SquaredEuclideanNorm,
    hash_k: false,
};

const PKEV2_HASH_CONFIG_V0_7_0: PkeV2HashConfig = PkeV2HashConfig {
    mode: PkeV2HashMode::Compact,
    proven_zero_bits_encoding: PkeV2ProvenZeroBitsEncoding::MsbZeroBitsCountOnly,
    hashed_bound_type: PkeV2HashedBoundType::SquaredEuclideanNorm,
    hash_k: false,
};

const PKEV2_HASH_CONFIG_V0_8_0: PkeV2HashConfig = PkeV2HashConfig {
    mode: PkeV2HashMode::Compact,
    proven_zero_bits_encoding: PkeV2ProvenZeroBitsEncoding::AnyBitAnySlot,
    hashed_bound_type: PkeV2HashedBoundType::InfinityNorm,
    hash_k: true,
};

impl From<PkeV2SupportedHashConfig> for PkeV2HashConfig {
    fn from(value: PkeV2SupportedHashConfig) -> Self {
        match value {
            PkeV2SupportedHashConfig::V0_4_0 => PKEV2_HASH_CONFIG_V0_4_0,
            PkeV2SupportedHashConfig::V0_7_0 => PKEV2_HASH_CONFIG_V0_7_0,
            PkeV2SupportedHashConfig::V0_8_0 => PKEV2_HASH_CONFIG_V0_8_0,
        }
    }
}

/// Encode the bits proven to be 0 in a plaintext list.
///
/// Today, the proof only allows to prove msb to be 0, and the same number of msb is used for every
/// slots. This function encodes the number of 0 bits in a more future proof way. This allows in the
/// future to prove any bit in any slot to be 0 without having to change the encoding.
///
/// For example, for a list of 6 elements, composed of 4 bits of plaintext that can take any value
/// and 1 bit of padding that is proven to be 0, we have:
/// -> k = 6, t = 2**5, msb_zero_padding_bit_count = 1
/// -> the base value to be encoded is 0b01111 (1 zero bit + 4 free bits). In lsb to msb this is
///    11110.
/// -> By copying the base value in lsb to msb 6 times, we get the following bit string:
///    bit: 11110|11110|11110|11110|11110|11110
///    pos: 01234 56789 abcde f ...
/// -> that is decomposed in bytes:
///    bit: 11110111 10111101 11101111 01111000
///    pos: 01234567 89abcdef ...
/// -> in the usual msb to lsb notation, the resulting bytes are:
///    bit: 0b11101111 0b10111101 0b11110111 0b11110
///    pos:   76543210   fedcba98   ...
fn encode_proven_zero_bits_anybit_anyslot(
    msb_zero_padding_bit_count: u64,
    t: u64,
    k: usize,
) -> Vec<u8> {
    let t_log2 = t.ilog2();

    assert!(msb_zero_padding_bit_count <= t_log2 as u64);
    assert!(k < u32::MAX as usize);

    let msb_zero_padding_bit_count = msb_zero_padding_bit_count as u32;
    let k = k as u32;

    let effective_t_log2 = t_log2 - msb_zero_padding_bit_count;

    // true since t is a u64
    assert!(effective_t_log2 <= 64);

    // This is the base value that will be encoded for all slots. For example, for 4 bits of
    // plaintext and one bit of padding proven to be 0, this will be 0b01111.
    // This value is stored in a u64 to support plaintext + padding size > 8.
    let encoded_base = if effective_t_log2 == 64 {
        u64::MAX
    } else {
        !(u64::MAX << effective_t_log2)
    };

    let number_bits_to_pack = k * t_log2;
    let packed_byte_len = number_bits_to_pack.div_ceil(u8::BITS);
    let mut packed = Vec::with_capacity(packed_byte_len as usize);

    // A temporary buffer of 128 bits that is used to store `encoded_base` + a remainder of at
    // most 7 bits.
    let mut bit_buffer: u128 = 0;
    let mut bits_in_buffer = 0;

    for _ in 0..k {
        // Add new bits to the temporary buffer
        bit_buffer |= (encoded_base as u128) << bits_in_buffer;
        bits_in_buffer += t_log2;

        // Dump the temporary buffer into the byte vec until there is less that a full byte left
        while bits_in_buffer >= u8::BITS {
            packed.push(bit_buffer as u8);
            bit_buffer >>= u8::BITS;
            bits_in_buffer -= u8::BITS;
        }
    }

    if bits_in_buffer > 0 {
        packed.push(bit_buffer as u8);
    }

    packed
}

impl PkeV2HashMode {
    /// Generate a list of scalars using the hash random oracle. The generated hashes are written to
    /// the `output` slice and a byte representation is returned
    fn gen_scalars_with_hash<Zp: FieldOps>(
        self,
        mut output: &mut [Zp],
        inputs: &[&[u8]],
        hash_fn: impl FnOnce(&mut [Zp], &[&[u8]]),
    ) -> Box<[u8]> {
        let mut scalar1 = Zp::ZERO;

        let scalars_gen = match self {
            PkeV2HashMode::BackwardCompat | PkeV2HashMode::Classical => &mut output,
            PkeV2HashMode::Compact => core::slice::from_mut(&mut scalar1),
        };

        hash_fn(scalars_gen, inputs);

        match self {
            PkeV2HashMode::BackwardCompat | PkeV2HashMode::Classical => output
                .iter()
                .flat_map(|x| x.to_le_bytes().as_ref().to_vec())
                .collect::<Box<[_]>>(),
            PkeV2HashMode::Compact => {
                generate_powers(scalar1, output);
                // since the content of the list is entirely defined by scalar1, it is not necessary
                // to hash the full list in the following steps
                Box::from(scalar1.to_le_bytes().as_ref())
            }
        }
    }

    fn gen_scalars<Zp: FieldOps>(self, output: &mut [Zp], inputs: &[&[u8]]) -> Box<[u8]> {
        self.gen_scalars_with_hash(output, inputs, Zp::hash)
    }

    /// Generates 128bits scalars that reduce the cost of multi exponentiations. This is
    /// not compatible with compact hashes since the scalars need to be independent, so a classical
    /// hash function should be used.
    ///
    /// # panic
    /// panics if self is `PkeV2HashMode::Compact`
    fn gen_scalars_128b<Zp: FieldOps>(self, output: &mut [Zp], inputs: &[&[u8]]) -> Box<[u8]> {
        if !self.supports_128b_scalars() {
            panic!("128b scalars optimization cannot be used in compact hash mode")
        };
        self.gen_scalars_with_hash(output, inputs, Zp::hash_128bit)
    }

    /// Checks if the hashing mode can be used with `gen_scalars_128`
    fn supports_128b_scalars(self) -> bool {
        match self {
            PkeV2HashMode::BackwardCompat | PkeV2HashMode::Classical => true,
            PkeV2HashMode::Compact => false,
        }
    }

    /// Encode the R matrix (defined as a matrix of -1, 0, 1) as bytes.
    fn encode_R(self, R: &[i8]) -> Box<[u8]> {
        // The representation is not specified in the mathematical description, so we are free to
        // chose a compact one as long as it is injective
        match self {
            PkeV2HashMode::BackwardCompat => {
                // Basic representation where each value is stored in a byte
                let R_coeffs = |i: usize, j: usize| R[i + j * 128];
                let columns = R.len() / 128;

                (0..128)
                    .flat_map(|i| (0..columns).map(move |j| R_coeffs(i, j) as u8))
                    .collect()
            }
            PkeV2HashMode::Compact | PkeV2HashMode::Classical => {
                // Since the R matrix is only composed of ternary values, we can pack them by group
                // of five instead of using a full u8 for each value
                R.chunks(5)
                    .map(|chunk| {
                        let mut packed: u8 = 0;
                        let mut power_of_3: u8 = 1;

                        // Cannot overflow since the max value is 3**5 = 243, which fits in a byte
                        for &byte in chunk {
                            let mapped = (byte + 1) as u8;
                            packed += mapped * power_of_3;
                            power_of_3 *= 3;
                        }
                        packed
                    })
                    .collect()
            }
        }
    }
}

// The scalar used for the proof are generated using sha3 as a random oracle. The inputs of the hash
// that generates a given scalar are reused for the subsequent hashes. We use the typestate pattern
// to propagate the inputs from one hash to the next.

struct RInputs<'a> {
    ds: &'a PKEv2DomainSeparators,
    sid_bytes: Box<[u8]>,
    metadata: &'a [u8],
    x_bytes: Box<[u8]>,
    C_hat_e_bytes: &'a [u8],
    C_e_bytes: &'a [u8],
    C_r_tilde_bytes: &'a [u8],
    D: usize,
    m: usize,
    n: usize,
    k: usize,
    d: usize,
    mode: PkeV2HashMode,
}

pub(crate) struct RHash<'a> {
    R_inputs: RInputs<'a>,
    R_bytes: Box<[u8]>,
}

impl<'a> RHash<'a> {
    pub(crate) fn new<G: Curve>(
        public: (&'a PublicParams<G>, &PublicCommit<G>),
        metadata: &'a [u8],
        C_hat_e_bytes: &'a [u8],
        C_e_bytes: &'a [u8],
        C_r_tilde_bytes: &'a [u8],
        config: PkeV2HashConfig,
    ) -> (Box<[i8]>, Self) {
        let (
            &PublicParams {
                g_lists: _,
                D: _,
                n,
                d,
                k: _,
                B_bound_squared: _,
                B_inf,
                q,
                t: t_input,
                msbs_zero_padding_bit_count,
                bound_type,
                sid,
                domain_separators: ref ds,
            },
            PublicCommit { a, b, c1, c2, .. },
        ) = public;

        let k = c2.len();
        let B_squared = inf_norm_bound_to_euclidean_squared(B_inf, d + k);
        let (_, D, _, m) = compute_crs_params(
            d,
            k,
            B_squared,
            t_input,
            msbs_zero_padding_bit_count,
            bound_type,
        );

        let encoded_zero_bits = config.proven_zero_bits_encoding.encode_proven_zero_bits(
            msbs_zero_padding_bit_count,
            t_input,
            k,
        );

        let hashed_bound = match config.hashed_bound_type {
            PkeV2HashedBoundType::SquaredEuclideanNorm => B_squared.to_le_bytes().to_vec(),
            PkeV2HashedBoundType::InfinityNorm => B_inf.to_le_bytes().to_vec(),
        };

        let hashed_k = if config.hash_k {
            (k as u64).to_le_bytes().to_vec()
        } else {
            Vec::new()
        };

        let x_bytes = [
            q.to_le_bytes().as_slice(),
            (d as u64).to_le_bytes().as_slice(),
            hashed_k.as_slice(),
            &hashed_bound,
            t_input.to_le_bytes().as_slice(),
            encoded_zero_bits.as_slice(),
            &*a.iter()
                .flat_map(|&x| x.to_le_bytes())
                .collect::<Box<[_]>>(),
            &*b.iter()
                .flat_map(|&x| x.to_le_bytes())
                .collect::<Box<[_]>>(),
            &*c1.iter()
                .flat_map(|&x| x.to_le_bytes())
                .collect::<Box<[_]>>(),
            &*c2.iter()
                .flat_map(|&x| x.to_le_bytes())
                .collect::<Box<[_]>>(),
        ]
        .iter()
        .copied()
        .flatten()
        .copied()
        .collect::<Box<[_]>>();

        let sid_bytes = Box::from(sid.to_le_bytes().as_slice());

        // make R_bar a random number generator from the given bytes
        use sha3::digest::{ExtendableOutput, Update, XofReader};

        let mut hasher = sha3::Shake256::default();
        for &data in &[
            ds.hash_R(),
            &sid_bytes,
            metadata,
            &x_bytes,
            C_hat_e_bytes,
            C_e_bytes,
            C_r_tilde_bytes,
        ] {
            hasher.update(data);
        }
        let mut R_bar = hasher.finalize_xof();
        let R = (0..128 * (2 * (d + k) + 4))
            .map(|_| {
                let mut byte = 0u8;
                R_bar.read(core::slice::from_mut(&mut byte));

                // take two bits
                match byte & 0b11 {
                    // probability 1/2
                    0 | 1 => 0,
                    // probability 1/4
                    2 => 1,
                    // probability 1/4
                    3 => -1,
                    _ => unreachable!(),
                }
            })
            .collect::<Box<[i8]>>();

        let R_bytes = config.mode.encode_R(&R);

        (
            R,
            Self {
                R_inputs: RInputs {
                    ds,
                    sid_bytes,
                    metadata,
                    x_bytes,
                    C_hat_e_bytes,
                    C_e_bytes,
                    C_r_tilde_bytes,
                    D,
                    m,
                    n,
                    k,
                    d,
                    mode: config.mode,
                },

                R_bytes,
            },
        )
    }

    fn phi_hash_inputs(&self, phi_inputs: &PhiInputs<'a>) -> [&[u8]; 9] {
        let Self { R_inputs, R_bytes } = self;

        [
            R_inputs.ds.hash_phi(),
            &R_inputs.sid_bytes,
            R_inputs.metadata,
            &R_inputs.x_bytes,
            R_bytes,
            R_inputs.C_hat_e_bytes,
            R_inputs.C_e_bytes,
            phi_inputs.C_R_bytes,
            R_inputs.C_r_tilde_bytes,
        ]
    }

    pub(crate) fn gen_phi<Zp: FieldOps>(self, C_R_bytes: &'a [u8]) -> ([Zp; 128], PhiHash<'a>) {
        let mode = self.R_inputs.mode;
        let phi_inputs = PhiInputs { C_R_bytes };

        let mut phi = [Zp::ZERO; 128];

        let phi_bytes = mode.gen_scalars(&mut phi, &self.phi_hash_inputs(&phi_inputs));

        (
            phi,
            PhiHash {
                R_inputs: self.R_inputs,
                phi_inputs,
                R_bytes: self.R_bytes,
                phi_bytes,
            },
        )
    }
}

struct PhiInputs<'a> {
    C_R_bytes: &'a [u8],
}

pub(crate) struct PhiHash<'a> {
    R_inputs: RInputs<'a>,
    R_bytes: Box<[u8]>,
    phi_inputs: PhiInputs<'a>,
    phi_bytes: Box<[u8]>,
}

impl<'a> PhiHash<'a> {
    fn xi_hash_inputs(&self, xi_inputs: &XiInputs<'a>) -> [&[u8]; 11] {
        let Self {
            R_inputs,
            R_bytes,
            phi_inputs,
            phi_bytes,
        } = self;

        match R_inputs.mode {
            PkeV2HashMode::BackwardCompat | PkeV2HashMode::Classical => [
                R_inputs.ds.hash_xi(),
                &R_inputs.sid_bytes,
                R_inputs.metadata,
                &R_inputs.x_bytes,
                R_inputs.C_hat_e_bytes,
                R_inputs.C_e_bytes,
                R_bytes,
                phi_bytes,
                phi_inputs.C_R_bytes,
                xi_inputs.C_hat_bin_bytes,
                R_inputs.C_r_tilde_bytes,
            ],
            PkeV2HashMode::Compact => [
                R_inputs.ds.hash_xi(),
                &R_inputs.sid_bytes,
                R_inputs.metadata,
                &R_inputs.x_bytes,
                R_inputs.C_hat_e_bytes,
                R_inputs.C_e_bytes,
                &[], // R is only hashed in phi in compact mode
                phi_bytes,
                phi_inputs.C_R_bytes,
                xi_inputs.C_hat_bin_bytes,
                R_inputs.C_r_tilde_bytes,
            ],
        }
    }

    pub(crate) fn gen_xi<Zp: FieldOps>(self, C_hat_bin_bytes: &'a [u8]) -> ([Zp; 128], XiHash<'a>) {
        let mode = self.R_inputs.mode;
        let xi_inputs = XiInputs { C_hat_bin_bytes };

        let mut xi = [Zp::ZERO; 128];

        let xi_bytes = mode.gen_scalars(&mut xi, &self.xi_hash_inputs(&xi_inputs));

        (
            xi,
            XiHash {
                R_inputs: self.R_inputs,
                R_bytes: self.R_bytes,
                phi_inputs: self.phi_inputs,
                phi_bytes: self.phi_bytes,
                xi_inputs,
                xi_bytes,
            },
        )
    }
}

struct XiInputs<'a> {
    C_hat_bin_bytes: &'a [u8],
}

pub(crate) struct XiHash<'a> {
    R_inputs: RInputs<'a>,
    R_bytes: Box<[u8]>,
    phi_inputs: PhiInputs<'a>,
    phi_bytes: Box<[u8]>,
    xi_inputs: XiInputs<'a>,
    xi_bytes: Box<[u8]>,
}

impl<'a> XiHash<'a> {
    fn y_hash_inputs(&self) -> [&[u8]; 12] {
        let Self {
            R_inputs,
            R_bytes,
            phi_inputs,
            phi_bytes,
            xi_inputs,
            xi_bytes,
        } = self;

        match R_inputs.mode {
            PkeV2HashMode::BackwardCompat | PkeV2HashMode::Classical => [
                R_inputs.ds.hash(),
                &R_inputs.sid_bytes,
                R_inputs.metadata,
                &R_inputs.x_bytes,
                R_bytes,
                phi_bytes,
                xi_bytes,
                R_inputs.C_hat_e_bytes,
                R_inputs.C_e_bytes,
                phi_inputs.C_R_bytes,
                xi_inputs.C_hat_bin_bytes,
                R_inputs.C_r_tilde_bytes,
            ],
            PkeV2HashMode::Compact => [
                R_inputs.ds.hash(),
                &R_inputs.sid_bytes,
                R_inputs.metadata,
                &R_inputs.x_bytes,
                &[], // R is only hashed in phi in compact mode
                phi_bytes,
                xi_bytes,
                R_inputs.C_hat_e_bytes,
                R_inputs.C_e_bytes,
                phi_inputs.C_R_bytes,
                xi_inputs.C_hat_bin_bytes,
                R_inputs.C_r_tilde_bytes,
            ],
        }
    }

    pub(crate) fn gen_y<Zp: FieldOps>(self) -> (Vec<Zp>, YHash<'a>) {
        let mode = self.R_inputs.mode;

        let mut y = vec![Zp::ZERO; self.R_inputs.D + 128 * self.R_inputs.m];
        let y_bytes = mode.gen_scalars(&mut y, &self.y_hash_inputs());

        (
            y,
            YHash {
                R_inputs: self.R_inputs,
                R_bytes: self.R_bytes,
                phi_inputs: self.phi_inputs,
                phi_bytes: self.phi_bytes,
                xi_inputs: self.xi_inputs,
                xi_bytes: self.xi_bytes,
                y_bytes,
            },
        )
    }
}

pub(crate) struct YHash<'a> {
    R_inputs: RInputs<'a>,
    R_bytes: Box<[u8]>,
    phi_inputs: PhiInputs<'a>,
    phi_bytes: Box<[u8]>,
    xi_inputs: XiInputs<'a>,
    xi_bytes: Box<[u8]>,
    y_bytes: Box<[u8]>,
}

impl<'a> YHash<'a> {
    fn t_hash_input(&self, t_inputs: &TInputs<'a>) -> [&[u8]; 14] {
        let Self {
            R_inputs,
            R_bytes,
            phi_inputs,
            phi_bytes,
            xi_inputs,
            xi_bytes,
            y_bytes,
        } = self;

        match R_inputs.mode {
            PkeV2HashMode::BackwardCompat | PkeV2HashMode::Classical => [
                R_inputs.ds.hash_t(),
                &R_inputs.sid_bytes,
                R_inputs.metadata,
                &R_inputs.x_bytes,
                y_bytes,
                phi_bytes,
                xi_bytes,
                R_inputs.C_hat_e_bytes,
                R_inputs.C_e_bytes,
                R_bytes,
                phi_inputs.C_R_bytes,
                xi_inputs.C_hat_bin_bytes,
                R_inputs.C_r_tilde_bytes,
                t_inputs.C_y_bytes,
            ],
            PkeV2HashMode::Compact => [
                R_inputs.ds.hash_t(),
                &R_inputs.sid_bytes,
                R_inputs.metadata,
                &R_inputs.x_bytes,
                y_bytes,
                phi_bytes,
                xi_bytes,
                R_inputs.C_hat_e_bytes,
                R_inputs.C_e_bytes,
                &[], // R is only hashed in phi in compact mode
                phi_inputs.C_R_bytes,
                xi_inputs.C_hat_bin_bytes,
                R_inputs.C_r_tilde_bytes,
                t_inputs.C_y_bytes,
            ],
        }
    }

    pub(crate) fn gen_t<Zp: FieldOps>(self, C_y_bytes: &'a [u8]) -> (Vec<Zp>, THash<'a>) {
        let mode = self.R_inputs.mode;
        let t_inputs = TInputs { C_y_bytes };

        let mut t = vec![Zp::ZERO; self.R_inputs.n];
        let t_bytes = if mode.supports_128b_scalars() {
            mode.gen_scalars_128b(&mut t, &self.t_hash_input(&t_inputs))
        } else {
            mode.gen_scalars(&mut t, &self.t_hash_input(&t_inputs))
        };

        (
            t,
            THash {
                R_inputs: self.R_inputs,
                R_bytes: self.R_bytes,
                phi_inputs: self.phi_inputs,
                phi_bytes: self.phi_bytes,
                xi_inputs: self.xi_inputs,
                xi_bytes: self.xi_bytes,
                y_bytes: self.y_bytes,
                t_inputs,
                t_bytes,
            },
        )
    }
}

struct TInputs<'a> {
    C_y_bytes: &'a [u8],
}

pub(crate) struct THash<'a> {
    R_inputs: RInputs<'a>,
    R_bytes: Box<[u8]>,
    phi_inputs: PhiInputs<'a>,
    phi_bytes: Box<[u8]>,
    xi_inputs: XiInputs<'a>,
    xi_bytes: Box<[u8]>,
    y_bytes: Box<[u8]>,
    t_inputs: TInputs<'a>,
    t_bytes: Box<[u8]>,
}

impl<'a> THash<'a> {
    fn theta_hash_input(&self) -> [&[u8]; 15] {
        let Self {
            R_inputs,
            phi_inputs,
            xi_inputs,
            t_inputs,
            t_bytes,
            R_bytes,
            phi_bytes,
            xi_bytes,
            y_bytes,
        } = self;

        match R_inputs.mode {
            PkeV2HashMode::BackwardCompat | PkeV2HashMode::Classical => [
                R_inputs.ds.hash_lmap(),
                &R_inputs.sid_bytes,
                R_inputs.metadata,
                &R_inputs.x_bytes,
                y_bytes,
                t_bytes,
                phi_bytes,
                xi_bytes,
                R_inputs.C_hat_e_bytes,
                R_inputs.C_e_bytes,
                R_bytes,
                phi_inputs.C_R_bytes,
                xi_inputs.C_hat_bin_bytes,
                R_inputs.C_r_tilde_bytes,
                t_inputs.C_y_bytes,
            ],
            PkeV2HashMode::Compact => [
                R_inputs.ds.hash_lmap(),
                &R_inputs.sid_bytes,
                R_inputs.metadata,
                &R_inputs.x_bytes,
                y_bytes,
                t_bytes,
                phi_bytes,
                xi_bytes,
                R_inputs.C_hat_e_bytes,
                R_inputs.C_e_bytes,
                &[], // R is only hashed in phi in compact mode
                phi_inputs.C_R_bytes,
                xi_inputs.C_hat_bin_bytes,
                R_inputs.C_r_tilde_bytes,
                t_inputs.C_y_bytes,
            ],
        }
    }

    pub(crate) fn gen_theta<Zp: FieldOps>(self) -> (Vec<Zp>, ThetaHash<'a>) {
        let mode = self.R_inputs.mode;

        let mut theta = vec![Zp::ZERO; self.R_inputs.d + self.R_inputs.k];
        let theta_bytes = mode.gen_scalars(&mut theta, &self.theta_hash_input());

        (
            theta,
            ThetaHash {
                R_inputs: self.R_inputs,
                R_bytes: self.R_bytes,
                phi_inputs: self.phi_inputs,
                phi_bytes: self.phi_bytes,
                xi_inputs: self.xi_inputs,
                xi_bytes: self.xi_bytes,
                y_bytes: self.y_bytes,
                t_inputs: self.t_inputs,
                t_bytes: self.t_bytes,
                theta_bytes,
            },
        )
    }
}

pub(crate) struct ThetaHash<'a> {
    R_inputs: RInputs<'a>,
    R_bytes: Box<[u8]>,
    phi_inputs: PhiInputs<'a>,
    phi_bytes: Box<[u8]>,
    xi_inputs: XiInputs<'a>,
    xi_bytes: Box<[u8]>,
    y_bytes: Box<[u8]>,
    t_inputs: TInputs<'a>,
    t_bytes: Box<[u8]>,
    theta_bytes: Box<[u8]>,
}

impl<'a> ThetaHash<'a> {
    fn omega_hash_input(&self) -> [&[u8]; 16] {
        let Self {
            R_inputs,
            R_bytes,
            phi_inputs,
            phi_bytes,
            xi_inputs,
            xi_bytes,
            y_bytes,
            t_inputs,
            t_bytes,
            theta_bytes,
        } = self;

        match self.R_inputs.mode {
            PkeV2HashMode::BackwardCompat | PkeV2HashMode::Classical => [
                R_inputs.ds.hash_w(),
                &R_inputs.sid_bytes,
                R_inputs.metadata,
                &R_inputs.x_bytes,
                y_bytes,
                t_bytes,
                phi_bytes,
                xi_bytes,
                theta_bytes,
                R_inputs.C_hat_e_bytes,
                R_inputs.C_e_bytes,
                R_bytes,
                phi_inputs.C_R_bytes,
                xi_inputs.C_hat_bin_bytes,
                R_inputs.C_r_tilde_bytes,
                t_inputs.C_y_bytes,
            ],
            PkeV2HashMode::Compact => [
                R_inputs.ds.hash_w(),
                &R_inputs.sid_bytes,
                R_inputs.metadata,
                &R_inputs.x_bytes,
                y_bytes,
                t_bytes,
                phi_bytes,
                xi_bytes,
                theta_bytes,
                R_inputs.C_hat_e_bytes,
                R_inputs.C_e_bytes,
                &[], // R is only hashed in phi in compact mode
                phi_inputs.C_R_bytes,
                xi_inputs.C_hat_bin_bytes,
                R_inputs.C_r_tilde_bytes,
                t_inputs.C_y_bytes,
            ],
        }
    }

    pub(crate) fn gen_omega<Zp: FieldOps>(self) -> (Vec<Zp>, OmegaHash<'a>) {
        let mode = self.R_inputs.mode;

        let mut omega = vec![Zp::ZERO; self.R_inputs.n];
        let omega_bytes = if mode.supports_128b_scalars() {
            mode.gen_scalars_128b(&mut omega, &self.omega_hash_input())
        } else {
            mode.gen_scalars(&mut omega, &self.omega_hash_input())
        };

        (
            omega,
            OmegaHash {
                R_inputs: self.R_inputs,
                R_bytes: self.R_bytes,
                phi_inputs: self.phi_inputs,
                phi_bytes: self.phi_bytes,
                xi_inputs: self.xi_inputs,
                xi_bytes: self.xi_bytes,
                y_bytes: self.y_bytes,
                t_inputs: self.t_inputs,
                t_bytes: self.t_bytes,
                theta_bytes: self.theta_bytes,
                omega_bytes,
            },
        )
    }
}

pub(crate) struct OmegaHash<'a> {
    R_inputs: RInputs<'a>,
    R_bytes: Box<[u8]>,
    phi_inputs: PhiInputs<'a>,
    phi_bytes: Box<[u8]>,
    xi_inputs: XiInputs<'a>,
    xi_bytes: Box<[u8]>,
    y_bytes: Box<[u8]>,
    t_inputs: TInputs<'a>,
    t_bytes: Box<[u8]>,
    theta_bytes: Box<[u8]>,
    omega_bytes: Box<[u8]>,
}

impl<'a> OmegaHash<'a> {
    fn delta_hash_input(&self) -> [&[u8]; 17] {
        let Self {
            R_inputs,
            R_bytes,
            phi_inputs,
            phi_bytes,
            xi_inputs,
            xi_bytes,
            y_bytes,
            t_inputs,
            t_bytes,
            theta_bytes,
            omega_bytes,
        } = self;

        match self.R_inputs.mode {
            PkeV2HashMode::BackwardCompat | PkeV2HashMode::Classical => [
                R_inputs.ds.hash_agg(),
                &R_inputs.sid_bytes,
                R_inputs.metadata,
                &R_inputs.x_bytes,
                y_bytes,
                t_bytes,
                phi_bytes,
                xi_bytes,
                theta_bytes,
                omega_bytes,
                R_inputs.C_hat_e_bytes,
                R_inputs.C_e_bytes,
                R_bytes,
                phi_inputs.C_R_bytes,
                xi_inputs.C_hat_bin_bytes,
                R_inputs.C_r_tilde_bytes,
                t_inputs.C_y_bytes,
            ],
            PkeV2HashMode::Compact => [
                R_inputs.ds.hash_agg(),
                &R_inputs.sid_bytes,
                R_inputs.metadata,
                &R_inputs.x_bytes,
                y_bytes,
                t_bytes,
                phi_bytes,
                xi_bytes,
                theta_bytes,
                omega_bytes,
                R_inputs.C_hat_e_bytes,
                R_inputs.C_e_bytes,
                &[], // R is only hashed in phi in compact mode
                phi_inputs.C_R_bytes,
                xi_inputs.C_hat_bin_bytes,
                R_inputs.C_r_tilde_bytes,
                t_inputs.C_y_bytes,
            ],
        }
    }

    pub(crate) fn gen_delta<Zp: FieldOps>(self) -> ([Zp; 7], DeltaHash<'a>) {
        let mut delta = [Zp::ZERO; 7];

        // Delta does not use the compact hash optimization
        Zp::hash(&mut delta, &self.delta_hash_input());
        let delta_bytes = delta
            .iter()
            .flat_map(|x| x.to_le_bytes().as_ref().to_vec())
            .collect::<Box<[_]>>();

        (
            delta,
            DeltaHash {
                R_inputs: self.R_inputs,
                R_bytes: self.R_bytes,
                phi_inputs: self.phi_inputs,
                phi_bytes: self.phi_bytes,
                xi_inputs: self.xi_inputs,
                xi_bytes: self.xi_bytes,
                y_bytes: self.y_bytes,
                t_inputs: self.t_inputs,
                t_bytes: self.t_bytes,
                theta_bytes: self.theta_bytes,
                omega_bytes: self.omega_bytes,
                delta_bytes,
            },
        )
    }
}

pub(crate) struct DeltaHash<'a> {
    R_inputs: RInputs<'a>,
    R_bytes: Box<[u8]>,
    phi_inputs: PhiInputs<'a>,
    phi_bytes: Box<[u8]>,
    xi_inputs: XiInputs<'a>,
    xi_bytes: Box<[u8]>,
    y_bytes: Box<[u8]>,
    t_inputs: TInputs<'a>,
    t_bytes: Box<[u8]>,
    theta_bytes: Box<[u8]>,
    omega_bytes: Box<[u8]>,
    delta_bytes: Box<[u8]>,
}

impl<'a> DeltaHash<'a> {
    fn z_hash_input(&self, z_inputs: &ZInputs<'a>) -> [&[u8]; 23] {
        let Self {
            R_inputs,
            R_bytes,
            phi_inputs,
            phi_bytes,
            xi_inputs,
            xi_bytes,
            y_bytes,
            t_inputs,
            t_bytes,
            theta_bytes,
            omega_bytes,
            delta_bytes,
        } = self;

        match R_inputs.mode {
            PkeV2HashMode::BackwardCompat => {
                [
                    R_inputs.ds.hash_z(),
                    &R_inputs.sid_bytes,
                    R_inputs.metadata,
                    &R_inputs.x_bytes,
                    y_bytes,
                    t_bytes,
                    phi_bytes,
                    &R_inputs.x_bytes, // x is duplicated but we keep it for backward compat
                    theta_bytes,
                    &[], // Omega is not included for backward compat
                    delta_bytes,
                    R_inputs.C_hat_e_bytes,
                    R_inputs.C_e_bytes,
                    R_bytes,
                    phi_inputs.C_R_bytes,
                    xi_inputs.C_hat_bin_bytes,
                    R_inputs.C_r_tilde_bytes,
                    t_inputs.C_y_bytes,
                    z_inputs.C_h1_bytes,
                    z_inputs.C_h2_bytes,
                    z_inputs.C_hat_t_bytes,
                    z_inputs.C_hat_h3_bytes,
                    z_inputs.C_hat_omega_bytes,
                ]
            }
            PkeV2HashMode::Classical => [
                R_inputs.ds.hash_z(),
                &R_inputs.sid_bytes,
                R_inputs.metadata,
                &R_inputs.x_bytes,
                y_bytes,
                t_bytes,
                phi_bytes,
                xi_bytes,
                theta_bytes,
                omega_bytes,
                delta_bytes,
                R_inputs.C_hat_e_bytes,
                R_inputs.C_e_bytes,
                R_bytes,
                phi_inputs.C_R_bytes,
                xi_inputs.C_hat_bin_bytes,
                R_inputs.C_r_tilde_bytes,
                t_inputs.C_y_bytes,
                z_inputs.C_h1_bytes,
                z_inputs.C_h2_bytes,
                z_inputs.C_hat_t_bytes,
                z_inputs.C_hat_h3_bytes,
                z_inputs.C_hat_omega_bytes,
            ],
            PkeV2HashMode::Compact => [
                R_inputs.ds.hash_z(),
                &R_inputs.sid_bytes,
                R_inputs.metadata,
                &R_inputs.x_bytes,
                y_bytes,
                t_bytes,
                phi_bytes,
                xi_bytes,
                theta_bytes,
                omega_bytes,
                delta_bytes,
                R_inputs.C_hat_e_bytes,
                R_inputs.C_e_bytes,
                &[], // R is only hashed in phi in compact mode
                phi_inputs.C_R_bytes,
                xi_inputs.C_hat_bin_bytes,
                R_inputs.C_r_tilde_bytes,
                t_inputs.C_y_bytes,
                z_inputs.C_h1_bytes,
                z_inputs.C_h2_bytes,
                z_inputs.C_hat_t_bytes,
                z_inputs.C_hat_h3_bytes,
                z_inputs.C_hat_omega_bytes,
            ],
        }
    }

    pub(crate) fn gen_z<Zp: FieldOps>(
        self,
        C_h1_bytes: &'a [u8],
        C_h2_bytes: &'a [u8],
        C_hat_t_bytes: &'a [u8],
        C_hat_h3_bytes: &'a [u8],
        C_hat_omega_bytes: &'a [u8],
    ) -> (Zp, ZHash<'a>) {
        let z_inputs = ZInputs {
            C_h1_bytes,
            C_h2_bytes,
            C_hat_t_bytes,
            C_hat_h3_bytes,
            C_hat_omega_bytes,
        };

        let mut z = Zp::ZERO;
        Zp::hash(core::slice::from_mut(&mut z), &self.z_hash_input(&z_inputs));

        (
            z,
            ZHash {
                R_inputs: self.R_inputs,
                R_bytes: self.R_bytes,
                phi_inputs: self.phi_inputs,
                phi_bytes: self.phi_bytes,
                xi_inputs: self.xi_inputs,
                xi_bytes: self.xi_bytes,
                y_bytes: self.y_bytes,
                t_inputs: self.t_inputs,
                t_bytes: self.t_bytes,
                theta_bytes: self.theta_bytes,
                omega_bytes: self.omega_bytes,
                delta_bytes: self.delta_bytes,
                z_inputs,
                z_bytes: Box::from(z.to_le_bytes().as_ref()),
            },
        )
    }
}

struct ZInputs<'a> {
    C_h1_bytes: &'a [u8],
    C_h2_bytes: &'a [u8],
    C_hat_t_bytes: &'a [u8],
    C_hat_h3_bytes: &'a [u8],
    C_hat_omega_bytes: &'a [u8],
}

pub(crate) struct ZHash<'a> {
    R_inputs: RInputs<'a>,
    R_bytes: Box<[u8]>,
    phi_inputs: PhiInputs<'a>,
    phi_bytes: Box<[u8]>,
    xi_inputs: XiInputs<'a>,
    xi_bytes: Box<[u8]>,
    y_bytes: Box<[u8]>,
    t_inputs: TInputs<'a>,
    t_bytes: Box<[u8]>,
    theta_bytes: Box<[u8]>,
    omega_bytes: Box<[u8]>,
    delta_bytes: Box<[u8]>,
    z_inputs: ZInputs<'a>,
    z_bytes: Box<[u8]>,
}

impl<'a> ZHash<'a> {
    fn chi_hash_input<'b>(
        &'b self,
        p_h1: &'b [u8],
        p_h2: &'b [u8],
        p_t: &'b [u8],
        p_h3: &'b [u8],
        p_omega: &'b [u8],
    ) -> [&'b [u8]; 29] {
        let Self {
            R_inputs,
            R_bytes,
            phi_inputs,
            phi_bytes,
            xi_inputs,
            xi_bytes,
            y_bytes,
            t_inputs,
            t_bytes,
            theta_bytes,
            omega_bytes,
            delta_bytes,
            z_inputs,
            z_bytes,
        } = self;

        match R_inputs.mode {
            PkeV2HashMode::BackwardCompat => [
                R_inputs.ds.hash_chi(),
                &R_inputs.sid_bytes,
                R_inputs.metadata,
                &R_inputs.x_bytes,
                y_bytes,
                t_bytes,
                phi_bytes,
                xi_bytes,
                theta_bytes,
                &[], // Omega is not included for backward compat
                delta_bytes,
                R_inputs.C_hat_e_bytes,
                R_inputs.C_e_bytes,
                R_bytes,
                phi_inputs.C_R_bytes,
                xi_inputs.C_hat_bin_bytes,
                R_inputs.C_r_tilde_bytes,
                t_inputs.C_y_bytes,
                z_inputs.C_h1_bytes,
                z_inputs.C_h2_bytes,
                z_inputs.C_hat_t_bytes,
                z_inputs.C_hat_h3_bytes,
                z_inputs.C_hat_omega_bytes,
                z_bytes,
                p_h1,
                p_h2,
                p_t,
                // p_h3 and p_omega are not hashed for backward compatibility reasons
                &[],
                &[],
            ],
            PkeV2HashMode::Classical => [
                R_inputs.ds.hash_chi(),
                &R_inputs.sid_bytes,
                R_inputs.metadata,
                &R_inputs.x_bytes,
                y_bytes,
                t_bytes,
                phi_bytes,
                xi_bytes,
                theta_bytes,
                omega_bytes,
                delta_bytes,
                R_inputs.C_hat_e_bytes,
                R_inputs.C_e_bytes,
                R_bytes,
                phi_inputs.C_R_bytes,
                xi_inputs.C_hat_bin_bytes,
                R_inputs.C_r_tilde_bytes,
                t_inputs.C_y_bytes,
                z_inputs.C_h1_bytes,
                z_inputs.C_h2_bytes,
                z_inputs.C_hat_t_bytes,
                z_inputs.C_hat_h3_bytes,
                z_inputs.C_hat_omega_bytes,
                z_bytes,
                p_h1,
                p_h2,
                p_t,
                p_h3,
                p_omega,
            ],
            PkeV2HashMode::Compact => [
                R_inputs.ds.hash_chi(),
                &R_inputs.sid_bytes,
                R_inputs.metadata,
                &R_inputs.x_bytes,
                y_bytes,
                t_bytes,
                phi_bytes,
                xi_bytes,
                theta_bytes,
                omega_bytes,
                delta_bytes,
                R_inputs.C_hat_e_bytes,
                R_inputs.C_e_bytes,
                &[], // R is only hashed in phi in compact mode
                phi_inputs.C_R_bytes,
                xi_inputs.C_hat_bin_bytes,
                R_inputs.C_r_tilde_bytes,
                t_inputs.C_y_bytes,
                z_inputs.C_h1_bytes,
                z_inputs.C_h2_bytes,
                z_inputs.C_hat_t_bytes,
                z_inputs.C_hat_h3_bytes,
                z_inputs.C_hat_omega_bytes,
                z_bytes,
                p_h1,
                p_h2,
                p_t,
                p_h3,
                p_omega,
            ],
        }
    }

    pub(crate) fn gen_chi<Zp: FieldOps>(
        self,
        p_h1: Zp,
        p_h2: Zp,
        p_t: Zp,
        p_h3_opt: Option<Zp>,
        p_omega_opt: Option<Zp>,
    ) -> Zp {
        let mut chi = Zp::ZERO;

        let p_h3 = p_h3_opt.map_or(Box::from([]), |p_h3| Box::from(p_h3.to_le_bytes().as_ref()));
        let p_omega = p_omega_opt.map_or(Box::from([]), |p_omega| {
            Box::from(p_omega.to_le_bytes().as_ref())
        });

        Zp::hash(
            core::slice::from_mut(&mut chi),
            &self.chi_hash_input(
                p_h1.to_le_bytes().as_ref(),
                p_h2.to_le_bytes().as_ref(),
                p_t.to_le_bytes().as_ref(),
                &p_h3,
                &p_omega,
            ),
        );

        chi
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_proven_zero_bits_encoding() {
        // Test the most common case
        let res = encode_proven_zero_bits_anybit_anyslot(1, 1 << 5, 6);
        // base value is 0b01111 (msb to lsb)
        // -> 11110 * 6 (lsb to msb)
        // -> 11110|11110|11110|11110|11110|11110 (lsb to msb)
        // -> 11110111 10111101 11101111 01111000 (lsb to msb)
        // -> 0b11101111 0b10111101 0b11110111 0b11110 (msb to lsb)
        let expected = vec![0b11101111, 0b10111101, 0b11110111, 0b11110];
        assert_eq!(expected, res);

        // Test a case where plaintext modulus log is > 8
        let res = encode_proven_zero_bits_anybit_anyslot(2, 1 << 9, 3);
        // base value is 0b001111111 (msb to lsb)
        // 111111100 * 3 (lsb to msb)
        // 111111100|111111100|111111100 (lsb to msb)
        // 11111110 01111111 00111111 10000000 (lsb to msb)
        // 0b1111111, 0b11111110, 0b11111100, 0b1 (msb to lsb)
        let expected = vec![0b1111111, 0b11111110, 0b11111100, 0b1];
        assert_eq!(expected, res);
    }
}
