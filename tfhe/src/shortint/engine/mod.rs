//! Module with the engine definitions.
//!
//! Engines are required to abstract cryptographic notions and efficiently manage memory from the
//! underlying `core_crypto` module.

use super::prelude::LweDimension;
use super::{PaddingBit, ShortintEncoding};
use crate::core_crypto::commons::computation_buffers::ComputationBuffers;
use crate::core_crypto::commons::generators::{
    DeterministicSeeder, EncryptionRandomGenerator, SecretRandomGenerator,
};
#[cfg(feature = "zk-pok")]
use crate::core_crypto::commons::math::random::RandomGenerator;
use crate::core_crypto::commons::math::random::{DefaultRandomGenerator, Seeder};
use crate::core_crypto::commons::parameters::CiphertextModulus;
use crate::core_crypto::entities::*;
use crate::core_crypto::prelude::{ContainerMut, GlweSize, UnsignedInteger};
use crate::core_crypto::seeders::new_seeder;
use crate::shortint::ciphertext::{Degree, MaxDegree};
use crate::shortint::prelude::PolynomialSize;
use crate::shortint::{CarryModulus, MessageModulus};
use std::cell::RefCell;
use std::fmt::Debug;

mod client_side;
mod public_side;
mod server_side;
#[cfg(feature = "experimental")]
mod wopbs;

thread_local! {
    static LOCAL_ENGINE: RefCell<ShortintEngine> = RefCell::new(ShortintEngine::new());
}

/// A buffer used to stored intermediate ciphertexts within an atomic pattern, to reduce the number
/// of allocations
#[derive(Default)]
struct CiphertextBuffer {
    // This buffer will be converted when needed into temporary lwe ciphertexts, eventually by
    // splitting u128 blocks into smaller scalars
    buffer: Vec<u128>,
}

impl CiphertextBuffer {
    fn as_lwe<Scalar>(
        &mut self,
        dim: LweDimension,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> LweCiphertextMutView<'_, Scalar>
    where
        Scalar: UnsignedInteger,
    {
        let elems_per_block = 128 / Scalar::BITS;

        let required_elems = dim.to_lwe_size().0;

        // Round up to have a full number of blocks
        let required_blocks = required_elems.div_ceil(elems_per_block);

        let buffer = if self.buffer.len() < required_blocks {
            self.buffer.resize(required_blocks, 0u128);
            self.buffer.as_mut_slice()
        } else {
            &mut self.buffer[..required_blocks]
        };

        // This should not panic as long as `Scalar::BITS` is a divisor of 128
        let buffer = bytemuck::try_cast_slice_mut(buffer).unwrap_or_else(|_| {
            panic!(
                "Scalar of size {} are not supported by the shortint engine",
                Scalar::BITS
            )
        });

        LweCiphertextMutView::from_container(&mut buffer[..required_elems], ciphertext_modulus)
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn fill_accumulator_with_encoding<F, C>(
    accumulator: &mut GlweCiphertext<C>,
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    input_message_modulus: MessageModulus,
    input_carry_modulus: CarryModulus,
    output_message_modulus: MessageModulus,
    output_carry_modulus: CarryModulus,
    f: F,
) -> u64
where
    C: ContainerMut<Element = u64>,
    F: Fn(u64) -> u64,
{
    assert_eq!(accumulator.polynomial_size(), polynomial_size);
    assert_eq!(accumulator.glwe_size(), glwe_size);

    // NB: Following path will not go `power_of_two_scaling_to_native_torus`
    // Thus keep value MSB aligned without considering real delta
    // i.e force modulus to be native
    let output_encoding = ShortintEncoding {
        ciphertext_modulus: CiphertextModulus::new_native(),
        message_modulus: output_message_modulus,
        carry_modulus: output_carry_modulus,
        padding_bit: PaddingBit::Yes,
    };

    let mut accumulator_view = accumulator.as_mut_view();

    accumulator_view.get_mut_mask().as_mut().fill(0);

    // Modulus of the msg contained in the msg bits and operations buffer
    let input_modulus_sup = (input_message_modulus.0 * input_carry_modulus.0) as usize;

    // N/(p/2) = size of each block
    let box_size = polynomial_size.0 / input_modulus_sup;

    let mut body = accumulator_view.get_mut_body();
    let accumulator_u64 = body.as_mut();

    // Tracking the max value of the function to define the degree later
    let mut max_value = 0;

    for i in 0..input_modulus_sup {
        let index = i * box_size;
        let f_eval = f(i as u64);
        max_value = max_value.max(f_eval);
        accumulator_u64[index..index + box_size].fill(output_encoding.encode(Cleartext(f_eval)).0);
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

pub(crate) fn fill_accumulator_no_encoding<F, C>(
    accumulator: &mut GlweCiphertext<C>,
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    f: F,
) where
    C: ContainerMut<Element = u64>,
    F: Fn(u64) -> u64,
{
    assert_eq!(accumulator.polynomial_size(), polynomial_size);
    assert_eq!(accumulator.glwe_size(), glwe_size);

    let mut accumulator_view = accumulator.as_mut_view();

    accumulator_view.get_mut_mask().as_mut().fill(0);

    let mut body = accumulator_view.get_mut_body();
    let accumulator_u64 = body.as_mut();

    for (i, value) in accumulator_u64.iter_mut().enumerate() {
        *value = f(i as u64);
    }
}

/// Fills a GlweCiphertext for use in a ManyLookupTable setting
pub(crate) fn fill_many_lut_accumulator<C>(
    accumulator: &mut GlweCiphertext<C>,
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    message_modulus: MessageModulus,
    carry_modulus: CarryModulus,
    functions: &[&dyn Fn(u64) -> u64],
) -> (MaxDegree, usize, Vec<Degree>)
where
    C: ContainerMut<Element = u64>,
{
    assert_eq!(accumulator.polynomial_size(), polynomial_size);
    assert_eq!(accumulator.glwe_size(), glwe_size);

    let encoding = ShortintEncoding {
        ciphertext_modulus: accumulator.ciphertext_modulus(),
        message_modulus,
        carry_modulus,
        padding_bit: PaddingBit::Yes,
    };

    let mut accumulator_view = accumulator.as_mut_view();

    accumulator_view.get_mut_mask().as_mut().fill(0);

    // Modulus of the msg contained in the msg bits and operations buffer
    let modulus_sup = (message_modulus.0 * carry_modulus.0) as usize;

    // N/(p/2) = size of each block
    let box_size = polynomial_size.0 / modulus_sup;

    let mut body = accumulator_view.get_mut_body();
    let accumulator_u64 = body.as_mut();
    // Clear in case we don't fill the full accumulator so that the remainder part is 0
    accumulator_u64.as_mut().fill(0u64);

    let fn_counts = functions.len();

    assert!(
        fn_counts <= modulus_sup / 2,
        "Cannot generate many lut accumulator for {fn_counts} functions, maximum possible is {}",
        modulus_sup / 2
    );

    // Max valid degree for a ciphertext when using the LUT we generate
    let max_degree = MaxDegree::new((modulus_sup / fn_counts - 1) as u64);

    let mut per_fn_output_degree = vec![Degree::new(0); fn_counts];

    // If MaxDegree == 1, we can have two input values 0 and 1, so we need MaxDegree + 1 boxes
    let single_function_sub_lut_size = (max_degree.get() as usize + 1) * box_size;

    for ((function_sub_lut, output_degree), function) in accumulator_u64
        .chunks_mut(single_function_sub_lut_size)
        .zip(per_fn_output_degree.iter_mut())
        .zip(functions)
    {
        for (msg_value, sub_lut_box) in function_sub_lut.chunks_exact_mut(box_size).enumerate() {
            let msg_value = msg_value as u64;
            let function_eval = function(msg_value);
            *output_degree = Degree::new((function_eval).max(output_degree.get()));
            sub_lut_box.fill(encoding.encode(Cleartext(function_eval)).0);
        }
    }

    let half_box_size = box_size / 2;

    // Negate the first half_box_size coefficients
    for a_i in accumulator_u64[0..half_box_size].iter_mut() {
        *a_i = (*a_i).wrapping_neg();
    }

    // Rotate the accumulator
    accumulator_u64.rotate_left(half_box_size);

    (
        max_degree,
        single_function_sub_lut_size,
        per_fn_output_degree,
    )
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

/// ShortintEngine
///
/// This 'engine' holds the necessary engines from [`core_crypto`](crate::core_crypto)
/// as well as the buffers that we want to keep around to save processing time.
///
/// This structs actually implements the logics into its methods.
pub struct ShortintEngine {
    /// A structure containing a single CSPRNG to generate secret key coefficients.
    pub(crate) secret_generator: SecretRandomGenerator<DefaultRandomGenerator>,
    /// A structure containing two CSPRNGs to generate material for encryption like public masks
    /// and secret errors.
    ///
    /// The [`EncryptionRandomGenerator`] contains two CSPRNGs, one publicly seeded used to
    /// generate mask coefficients and one privately seeded used to generate errors during
    /// encryption.
    pub(crate) encryption_generator: EncryptionRandomGenerator<DefaultRandomGenerator>,
    /// A seeder that can be called to generate 128 bits seeds, useful to create new
    /// [`EncryptionRandomGenerator`] to encrypt seeded types.
    pub(crate) seeder: DeterministicSeeder<DefaultRandomGenerator>,
    #[cfg(feature = "zk-pok")]
    pub(crate) random_generator: RandomGenerator<DefaultRandomGenerator>,
    computation_buffers: ComputationBuffers,
    ciphertext_buffers: CiphertextBuffer,
}

impl Default for ShortintEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ShortintEngine {
    /// Safely gives access to the `thead_local` shortint engine
    /// to call one (or many) of its method.
    #[inline]
    pub fn with_thread_local_mut<F, R>(func: F) -> R
    where
        F: FnOnce(&mut Self) -> R,
    {
        LOCAL_ENGINE.with(|engine_cell| {
            if let Ok(mut thread_engine) = engine_cell.try_borrow_mut() {
                func(&mut thread_engine)
            } else {
                // The thread engine might be unavailable at this point.
                // This might happen for example if we have the following call stack:
                // - rayon::par_iter
                // - with_thread_local_mut
                // - rayon::par_iter
                // In that case a task from the outer par_iter will be descheduled when reaching the
                // inner par_iter. Another outer task might be scheduled on the same
                // thread and try to access the engine again.
                //
                // To avoid this, instead of crashing we create a temporary engine for the current
                // task. This might incur a performance overhead but it's better
                // than a panic. This should not affect determinism since the task
                // would have been scheduled on an undefined thread with an engine
                // in an unknown state anyways.
                func(&mut Self::new())
            }
        })
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
            DeterministicSeeder::<DefaultRandomGenerator>::new(root_seeder.seed());

        // Note that the operands are evaluated from left to right for Rust Struct expressions
        // See: https://doc.rust-lang.org/stable/reference/expressions.html?highlight=left#evaluation-order-of-operands
        Self {
            secret_generator: SecretRandomGenerator::new(deterministic_seeder.seed()),
            encryption_generator: EncryptionRandomGenerator::new(
                deterministic_seeder.seed(),
                &mut deterministic_seeder,
            ),
            #[cfg(feature = "zk-pok")]
            random_generator: RandomGenerator::new(deterministic_seeder.seed()),
            seeder: deterministic_seeder,
            computation_buffers: ComputationBuffers::default(),
            ciphertext_buffers: CiphertextBuffer::default(),
        }
    }

    /// Return the work buffers for the given engine
    ///
    /// - Ciphertext buffer for intermediate results within an atomic pattern
    /// - [`ComputationBuffers`] used by the FFT during the PBS
    pub fn get_buffers<Scalar>(
        &mut self,
        lwe_dimension: LweDimension,
        ciphertext_modulus: CiphertextModulus<Scalar>,
    ) -> (LweCiphertextMutView<'_, Scalar>, &mut ComputationBuffers)
    where
        Scalar: UnsignedInteger,
    {
        (
            self.ciphertext_buffers
                .as_lwe::<Scalar>(lwe_dimension, ciphertext_modulus),
            &mut self.computation_buffers,
        )
    }

    pub fn get_computation_buffers(&mut self) -> &mut ComputationBuffers {
        &mut self.computation_buffers
    }
}

#[cfg(test)]
mod test {
    use rand::Rng;
    use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

    use crate::shortint::parameters::test_params::TEST_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    use crate::shortint::{CompactPrivateKey, CompactPublicKey};

    /// Test the case where a thread is reused by rayon and thread engine will be already borrowed
    #[test]
    fn test_engine_thread_reuse_ci_run_filter() {
        let mut rng = rand::rng();
        let param_pke = TEST_PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
        let packed_modulus = param_pke.message_modulus.0 * param_pke.carry_modulus.0;

        let compact_private_key = CompactPrivateKey::new(param_pke);
        let pk = CompactPublicKey::new(&compact_private_key);

        // Should be enough to trigger a thread re-use on all cpu config
        let elements = 500;
        let fhe_uint_count = 16;

        let messages = (0..elements)
            .map(|_| {
                let input_msg: u64 = rng.gen_range(0..packed_modulus);
                vec![input_msg; fhe_uint_count]
            })
            .collect::<Vec<_>>();

        // Trigger the pattern par_iter -> engine borrow -> par_iter
        messages.par_iter().for_each(|msg| {
            pk.encrypt_iter_with_modulus(msg.iter().copied(), packed_modulus);
        })
    }
}
