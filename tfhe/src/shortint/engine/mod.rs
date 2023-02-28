//! Module with the engine definitions.
//!
//! Engines are required to abstract cryptographic notions and efficiently manage memory from the
//! underlying `core_crypto` module.

use crate::core_crypto::algorithms::*;
use crate::core_crypto::commons::computation_buffers::ComputationBuffers;
use crate::core_crypto::commons::generators::{
    DeterministicSeeder, EncryptionRandomGenerator, SecretRandomGenerator,
};
use crate::core_crypto::commons::math::random::{ActivatedRandomGenerator, Seeder};
use crate::core_crypto::commons::parameters::*;
use crate::core_crypto::entities::*;
use crate::core_crypto::seeders::new_seeder;
use crate::shortint::ciphertext::Degree;
use crate::shortint::server_key::Accumulator;
use crate::shortint::ServerKey;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt::Debug;

mod client_side;
mod public_side;
mod server_side;
#[cfg(not(feature = "__wasm_api"))]
mod wopbs;

thread_local! {
    static LOCAL_ENGINE: RefCell<ShortintEngine> = RefCell::new(ShortintEngine::new());
}

/// Stores buffers associated to a ServerKey
pub struct Buffers {
    pub(crate) accumulator: GlweCiphertextOwned<u64>,
    pub(crate) buffer_lwe_after_ks: LweCiphertextOwned<u64>,
}

/// This allows to store and retrieve the `Buffers`
/// corresponding to a `ServerKey` in a `BTreeMap`
#[derive(Debug, Copy, Clone, PartialOrd, Ord, PartialEq, Eq)]
struct KeyId {
    lwe_dim_after_ks: usize,
    // Also accumulator size
    glwe_size: GlweSize,
    poly_size: PolynomialSize,
}

impl ServerKey {
    #[inline]
    fn key_id(&self) -> KeyId {
        KeyId {
            lwe_dim_after_ks: self.key_switching_key.output_key_lwe_dimension().0,
            glwe_size: self.bootstrapping_key.glwe_size(),
            poly_size: self.bootstrapping_key.polynomial_size(),
        }
    }
}

/// Simple wrapper around [`std::error::Error`] to be able to
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
    secret_generator: SecretRandomGenerator<ActivatedRandomGenerator>,
    /// A structure containing two CSPRNGs to generate material for encryption like public masks
    /// and secret errors.
    ///
    /// The [`EncryptionRandomGenerator`] contains two CSPRNGs, one publicly seeded used to
    /// generate mask coefficients and one privately seeded used to generate errors during
    /// encryption.
    encryption_generator: EncryptionRandomGenerator<ActivatedRandomGenerator>,
    /// A seeder that can be called to generate 128 bits seeds, useful to create new
    /// [`EncryptionRandomGenerator`] to encrypt seeded types.
    seeder: DeterministicSeeder<ActivatedRandomGenerator>,
    computation_buffers: ComputationBuffers,
    ciphertext_buffers: BTreeMap<KeyId, Buffers>,
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

    /// Create a new shortint engine
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
        let mut root_seeder = new_seeder();

        Self::new_from_seeder(root_seeder.as_mut())
    }

    pub fn new_from_seeder(root_seeder: &mut dyn Seeder) -> Self {
        let mut deterministic_seeder =
            DeterministicSeeder::<ActivatedRandomGenerator>::new(root_seeder.seed());

        // Note that the operands are evaluated from left to right for Rust Struct expressions
        // See: https://doc.rust-lang.org/stable/reference/expressions.html?highlight=left#evaluation-order-of-operands
        Self {
            secret_generator: SecretRandomGenerator::new(deterministic_seeder.seed()),
            encryption_generator: EncryptionRandomGenerator::new(
                deterministic_seeder.seed(),
                &mut deterministic_seeder,
            ),
            seeder: deterministic_seeder,
            computation_buffers: Default::default(),
            ciphertext_buffers: Default::default(),
        }
    }

    fn generate_accumulator_with_engine<F>(
        server_key: &ServerKey,
        f: F,
    ) -> EngineResult<Accumulator>
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

        // Tracking the max value of the function to define the degree later
        let mut max_value = 0;

        // This accumulator extracts the carry bits
        for i in 0..modulus_sup {
            let index = i * box_size;
            accumulator_u64[index..index + box_size]
                .iter_mut()
                .for_each(|a| {
                    let f_eval = f(i as u64);
                    *a = f_eval * delta;
                    max_value = max_value.max(f_eval);
                });
        }

        let half_box_size = box_size / 2;

        // Negate the first half_box_size coefficients
        for a_i in accumulator_u64[0..half_box_size].iter_mut() {
            *a_i = (*a_i).wrapping_neg();
        }

        // Rotate the accumulator
        accumulator_u64.rotate_left(half_box_size);

        // Everywhere
        let accumulator_plaintext = PlaintextListOwned::from_container(accumulator_u64);

        let accumulator = allocate_and_trivially_encrypt_new_glwe_ciphertext(
            server_key.bootstrapping_key.glwe_size(),
            &accumulator_plaintext,
        );

        Ok(Accumulator {
            acc: accumulator,
            degree: Degree(max_value as usize),
        })
    }

    fn generate_accumulator_bivariate_with_engine<F>(
        server_key: &ServerKey,
        f: F,
    ) -> EngineResult<Accumulator>
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

    /// Return the [`Buffers`] and [`ComputationBuffers`] for the given `ServerKey`
    ///
    /// Takes care creating the [`Buffers`] if they do not exists for the given key
    pub fn buffers_for_key(
        &mut self,
        server_key: &ServerKey,
    ) -> (&mut Buffers, &mut ComputationBuffers) {
        let key = server_key.key_id();
        // To make borrow checker happy
        let buffers_map = &mut self.ciphertext_buffers;
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
                accumulator: accumulator.acc,
                buffer_lwe_after_ks,
            }
        });

        (buffers, &mut self.computation_buffers)
    }
}
