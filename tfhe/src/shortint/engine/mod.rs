//! Module with the engine definitions.
//!
//! Engines are required to abstract cryptographic notions and efficiently manage memory from the
//! underlying `core_crypto` module.

use crate::core_crypto::commons::computation_buffers::ComputationBuffers;
use crate::core_crypto::commons::generators::{
    DeterministicSeeder, EncryptionRandomGenerator, SecretRandomGenerator,
};
use crate::core_crypto::commons::math::random::{ActivatedRandomGenerator, Seeder};
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::ContainerMut;
use crate::core_crypto::seeders::new_seeder;
use crate::shortint::ServerKey;
use std::cell::RefCell;
use std::fmt::Debug;

mod client_side;
mod public_side;
mod server_side;
mod wopbs;

thread_local! {
    static LOCAL_ENGINE: RefCell<ShortintEngine> = RefCell::new(ShortintEngine::new());
}

pub struct BuffersRef<'a> {
    // For the intermediate keyswitch result in the case of a big ciphertext
    pub(crate) buffer_lwe_after_ks: LweCiphertextMutView<'a, u64>,
    // For the intermediate PBS result in the case of a smallciphertext
    pub(crate) buffer_lwe_after_pbs: LweCiphertextMutView<'a, u64>,
}

#[derive(Default)]
struct Memory {
    buffer: Vec<u64>,
}

impl Memory {
    fn as_buffers(&mut self, server_key: &ServerKey) -> BuffersRef<'_> {
        let num_elem_in_lwe_after_ks = server_key.key_switching_key.output_lwe_size().0;
        let num_elem_in_lwe_after_pbs = server_key
            .bootstrapping_key
            .output_lwe_dimension()
            .to_lwe_size()
            .0;

        let total_elem_needed = num_elem_in_lwe_after_ks + num_elem_in_lwe_after_pbs;

        let all_elements = if self.buffer.len() < total_elem_needed {
            self.buffer.resize(total_elem_needed, 0u64);
            self.buffer.as_mut_slice()
        } else {
            &mut self.buffer[..total_elem_needed]
        };

        let (after_ks_elements, after_pbs_elements) =
            all_elements.split_at_mut(num_elem_in_lwe_after_ks);

        let buffer_lwe_after_ks =
            LweCiphertextMutView::from_container(after_ks_elements, server_key.ciphertext_modulus);
        let buffer_lwe_after_pbs =
            LweCiphertextMutView::from_container(after_pbs_elements, server_key.ciphertext_modulus);

        BuffersRef {
            buffer_lwe_after_ks,
            buffer_lwe_after_pbs,
        }
    }
}

pub(crate) fn fill_accumulator<F, C>(
    accumulator: &mut GlweCiphertext<C>,
    server_key: &ServerKey,
    f: F,
) -> u64
where
    C: ContainerMut<Element = u64>,
    F: Fn(u64) -> u64,
{
    assert_eq!(
        accumulator.polynomial_size(),
        server_key.bootstrapping_key.polynomial_size()
    );
    assert_eq!(
        accumulator.glwe_size(),
        server_key.bootstrapping_key.glwe_size()
    );

    let mut accumulator_view = accumulator.as_mut_view();

    accumulator_view.get_mut_mask().as_mut().fill(0);

    // Modulus of the msg contained in the msg bits and operations buffer
    let modulus_sup = server_key.message_modulus.0 * server_key.carry_modulus.0;

    // N/(p/2) = size of each block
    let box_size = server_key.bootstrapping_key.polynomial_size().0 / modulus_sup;

    // Value of the shift we multiply our messages by
    let delta = (1_u64 << 63) / (server_key.message_modulus.0 * server_key.carry_modulus.0) as u64;

    let mut body = accumulator_view.get_mut_body();
    let accumulator_u64 = body.as_mut();

    // Tracking the max value of the function to define the degree later
    let mut max_value = 0;

    // This accumulator extracts the carry bits
    for i in 0..modulus_sup {
        let index = i * box_size;
        let f_eval = f(i as u64);
        max_value = max_value.max(f_eval);
        accumulator_u64[index..index + box_size].fill(f_eval * delta);
    }

    let half_box_size = box_size / 2;

    // Negate the first half_box_size coefficients
    for a_i in accumulator_u64[0..half_box_size].iter_mut() {
        *a_i = (*a_i).wrapping_neg();
    }

    // Rotate the accumulator
    accumulator_u64.rotate_left(half_box_size);

    max_value
}

/// Simple wrapper around [`std::error::Error`] to be able to
/// forward all the possible `EngineError` type from [`core_crypto`](crate::core_crypto)
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

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.error)
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
    /// The [`EncryptionRandomGenerator`] contains two CSPRNGs, one publicly seeded used to
    /// generate mask coefficients and one privately seeded used to generate errors during
    /// encryption.
    pub(crate) encryption_generator: EncryptionRandomGenerator<ActivatedRandomGenerator>,
    /// A seeder that can be called to generate 128 bits seeds, useful to create new
    /// [`EncryptionRandomGenerator`] to encrypt seeded types.
    pub(crate) seeder: DeterministicSeeder<ActivatedRandomGenerator>,
    pub(crate) computation_buffers: ComputationBuffers,
    ciphertext_buffers: Memory,
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
            computation_buffers: ComputationBuffers::default(),
            ciphertext_buffers: Memory::default(),
        }
    }

    /// Return the [`BuffersRef`] and [`ComputationBuffers`] for the given `ServerKey`
    pub fn get_buffers(
        &mut self,
        server_key: &ServerKey,
    ) -> (BuffersRef<'_>, &mut ComputationBuffers) {
        (
            self.ciphertext_buffers.as_buffers(server_key),
            &mut self.computation_buffers,
        )
    }
}
