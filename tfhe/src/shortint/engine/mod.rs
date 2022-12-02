use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::crypto::secret::generators::{
    EncryptionRandomGenerator, SecretRandomGenerator,
};
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::{Seeder, *};
use crate::seeders::new_seeder;
use crate::shortint::ServerKey;
use core::mem::MaybeUninit;
use dyn_stack::DynStack;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt::Debug;

mod client_side;
mod public_side;
mod server_side;
#[cfg(not(feature = "__wasm_api"))]
mod wopbs;

use crate::core_crypto::backends::default::engines::ActivatedRandomGenerator;
use crate::core_crypto::commons::crypto::secret::generators::DeterministicSeeder;

thread_local! {
    static LOCAL_ENGINE: RefCell<ShortintEngine> = RefCell::new(ShortintEngine::new());
}

/// Stores buffers associated to a ServerKey
pub struct Buffers {
    pub(crate) accumulator: GlweCiphertext<u64>,
    pub(crate) buffer_lwe_after_ks: LweCiphertext<u64>,
}

pub struct FftBuffers {
    memory: Vec<MaybeUninit<u8>>,
}

impl FftBuffers {
    pub fn new() -> Self {
        FftBuffers { memory: Vec::new() }
    }

    pub fn resize(&mut self, capacity: usize) {
        self.memory.resize_with(capacity, MaybeUninit::uninit);
    }

    pub fn stack(&mut self) -> DynStack<'_> {
        DynStack::new(&mut self.memory)
    }
}

impl Default for FftBuffers {
    fn default() -> Self {
        Self::new()
    }
}

/// This allows to store and retrieve the `Buffers`
/// corresponding to a `ServerKey` in a `BTreeMap`
#[derive(Debug, Copy, Clone, PartialOrd, Ord, PartialEq, Eq)]
struct KeyId {
    lwe_dim_after_pbs: usize,
    // Also accumulator size
    glwe_size: GlweSize,
    poly_size: PolynomialSize,
}

impl ServerKey {
    #[inline]
    fn key_id(&self) -> KeyId {
        KeyId {
            lwe_dim_after_pbs: self.bootstrapping_key.output_lwe_dimension().0,
            glwe_size: self.bootstrapping_key.glwe_size(),
            poly_size: self.bootstrapping_key.polynomial_size(),
        }
    }
}

/// Simple wrapper around `std::error::Error` to be able to
/// forward all the possible `EngineError` type from [`core_cryto`](crate::core_crypto)
#[allow(dead_code)]
#[derive(Debug)]
pub struct EngineError {
    error: Box<dyn std::error::Error>,
}

impl<T> From<T> for EngineError
where
    T: std::error::Error + 'static,
{
    fn from(error: T) -> Self {
        Self {
            error: Box::new(error),
        }
    }
}

pub(crate) type EngineResult<T> = Result<T, EngineError>;

/// ShortintEngine
///
/// This 'engine' holds the necessary engines from [`core_crypto`](crate::core_crypto)
/// as well as the buffers that we want to keep around to save processing time.
///
/// This structs actually implements the logics into its methods.
pub struct ShortintEngine {
    /// A structure containing a single CSPRNG to generate secret key coefficients.
    pub(crate) secret_generator: SecretRandomGenerator<ActivatedRandomGenerator>,
    /// A structure containing two CSPRNGs to generate material for encryption like public masks
    /// and secret errors.
    ///
    /// The [`ImplEncryptionRandomGenerator`] contains two CSPRNGs, one publicly seeded used to
    /// generate mask coefficients and one privately seeded used to generate errors during
    /// encryption.
    pub(crate) encryption_generator: EncryptionRandomGenerator<ActivatedRandomGenerator>,
    pub(crate) fft_buffers: FftBuffers,
    buffers: BTreeMap<KeyId, Buffers>,
}

impl ShortintEngine {
    /// Safely gives access to the `thead_local` shortint engine
    /// to call one (or many) of its method.
    #[inline]
    pub fn with_thread_local_mut<F, R>(func: F) -> R
    where
        F: FnOnce(&mut Self) -> R,
    {
        LOCAL_ENGINE.with(|engine_cell| func(&mut engine_cell.borrow_mut()))
    }

    /// Creates a new shortint engine
    ///
    /// Creating a `ShortintEngine` should not be needed, as each
    /// rust thread gets its own `thread_local` engine created automatically,
    /// see [ShortintEngine::with_thread_local_mut]
    ///
    ///
    /// # Panics
    ///
    /// This will panic if the `CoreEngine` failed to create.
    pub fn new() -> Self {
        let root_seeder = new_seeder();

        Self::new_from_seeder(root_seeder)
    }

    pub fn new_from_seeder(mut root_seeder: Box<dyn Seeder>) -> Self {
        let mut deterministic_seeder =
            DeterministicSeeder::<ActivatedRandomGenerator>::new(root_seeder.seed());

        // Note that the operands are evaluated from left to right for Rust Struct expressions
        // See: https://doc.rust-lang.org/stable/reference/expressions.html?highlight=left#evaluation-order-of-operands
        // So parameters is moved in seeder after the calls to seed and the potential calls when it
        // is passed as_mut in EncryptionRandomGenerator::new
        Self {
            secret_generator: SecretRandomGenerator::new(deterministic_seeder.seed()),
            encryption_generator: EncryptionRandomGenerator::new(
                deterministic_seeder.seed(),
                &mut deterministic_seeder,
            ),
            fft_buffers: Default::default(),
            buffers: Default::default(),
        }
    }

    fn generate_accumulator_with_engine<F>(
        server_key: &ServerKey,
        f: F,
    ) -> EngineResult<GlweCiphertext<u64>>
    where
        F: Fn(u64) -> u64,
    {
        // Modulus of the msg contained in the msg bits and operations buffer
        let modulus_sup = server_key.message_modulus.0 * server_key.carry_modulus.0;

        // N/(p/2) = size of each block
        let box_size = server_key.bootstrapping_key.polynomial_size().0 / modulus_sup;

        // Value of the shift we multiply our messages by
        let delta =
            (1_u64 << 63) / (server_key.message_modulus.0 * server_key.carry_modulus.0) as u64;

        // Create the accumulator
        let mut accumulator_u64 = vec![0_u64; server_key.bootstrapping_key.polynomial_size().0];

        // This accumulator extracts the carry bits
        for i in 0..modulus_sup {
            let index = i * box_size;
            accumulator_u64[index..index + box_size]
                .iter_mut()
                .for_each(|a| *a = f(i as u64) * delta);
        }

        let half_box_size = box_size / 2;

        // Negate the first half_box_size coefficients
        for a_i in accumulator_u64[0..half_box_size].iter_mut() {
            *a_i = (*a_i).wrapping_neg();
        }

        // Rotate the accumulator
        accumulator_u64.rotate_left(half_box_size);

        // Everywhere
        let accumulator_plaintext = PlaintextList::from_container(accumulator_u64);

        let accumulator = allocate_and_trivially_encrypt_new_glwe_ciphertext(
            server_key.bootstrapping_key.glwe_size(),
            &accumulator_plaintext,
        );

        Ok(accumulator)
    }

    fn generate_accumulator_bivariate_with_engine<F>(
        server_key: &ServerKey,
        f: F,
    ) -> EngineResult<GlweCiphertext<u64>>
    where
        F: Fn(u64, u64) -> u64,
    {
        let modulus = server_key.message_modulus.0 as u64;
        let wrapped_f = |input: u64| -> u64 {
            let lhs = (input / modulus) % modulus;
            let rhs = input % modulus;

            f(lhs, rhs)
        };
        ShortintEngine::generate_accumulator_with_engine(server_key, wrapped_f)
    }

    /// Returns the `Buffers` for the given `ServerKey`
    ///
    /// Takes care creating the buffers if they do not exists for the given key
    ///
    /// This also `&mut CoreEngine` to simply borrow checking for the caller
    /// (since returned buffers are borrowed from `self`, using the `self.engine`
    /// wouldn't be possible after calling `buffers_for_key`)
    pub fn buffers_for_key(&mut self, server_key: &ServerKey) -> (&mut Buffers, &mut FftBuffers) {
        let key = server_key.key_id();
        // To make borrow checker happy
        let buffers_map = &mut self.buffers;
        let buffers = buffers_map.entry(key).or_insert_with(|| {
            let accumulator = Self::generate_accumulator_with_engine(server_key, |n| {
                n % server_key.message_modulus.0 as u64
            })
            .unwrap();

            // Allocate the buffer for the output of the PBS
            let zero_plaintext = Plaintext(0_u64);
            let buffer_lwe_after_ks = allocate_and_trivially_encrypt_new_lwe_ciphertext(
                server_key
                    .key_switching_key
                    .output_key_lwe_dimension()
                    .to_lwe_size(),
                zero_plaintext,
            );

            Buffers {
                accumulator,
                buffer_lwe_after_ks,
            }
        });

        (buffers, &mut self.fft_buffers)
    }
}
