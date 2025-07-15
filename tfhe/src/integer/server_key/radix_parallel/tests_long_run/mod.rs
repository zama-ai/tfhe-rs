use crate::core_crypto::commons::generators::DeterministicSeeder;
use crate::core_crypto::prelude::CastFrom;
use crate::integer::block_decomposition::DecomposableInto;
use crate::integer::{
    BooleanBlock, IntegerCiphertext, RadixCiphertext, RadixClientKey, SignedRadixCiphertext,
};
use crate::shortint::parameters::NoiseLevel;
use rand::Rng;
use tfhe_csprng::generators::DefaultRandomGenerator;
use tfhe_csprng::seeders::{Seed, Seeder};

pub(crate) mod test_erc20;
pub(crate) mod test_random_op_sequence;
pub(crate) mod test_signed_erc20;
pub(crate) mod test_signed_random_op_sequence;
pub(crate) const NB_CTXT_LONG_RUN: usize = 32;
pub(crate) const NB_TESTS_LONG_RUN: usize = 20000;
pub(crate) const NB_TESTS_LONG_RUN_MINIMAL: usize = 200;

pub(crate) fn get_long_test_iterations() -> usize {
    static ENV_KEY_LONG_TESTS: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

    let is_long_tests_minimal = *ENV_KEY_LONG_TESTS.get_or_init(|| {
        std::env::var("TFHE_RS_TEST_LONG_TESTS_MINIMAL")
            .is_ok_and(|val| val.to_uppercase() == "TRUE")
    });

    if is_long_tests_minimal {
        NB_TESTS_LONG_RUN_MINIMAL
    } else {
        NB_TESTS_LONG_RUN
    }
}

#[derive(Clone)]
pub(crate) struct TestDataSample<P, C> {
    pub(crate) p: P,
    pub(crate) c: C,
    pub(crate) producer: (String, usize),
}

pub trait RadixEncryptable {
    type Output;

    fn encrypt(&self, key: &RadixClientKey) -> Self::Output;
}

impl RadixEncryptable for u64 {
    type Output = RadixCiphertext;

    fn encrypt(&self, key: &RadixClientKey) -> Self::Output {
        key.encrypt(*self)
    }
}

impl RadixEncryptable for i64 {
    type Output = SignedRadixCiphertext;

    fn encrypt(&self, key: &RadixClientKey) -> Self::Output {
        key.encrypt_signed(*self)
    }
}

struct RandomOpSequenceDataGenerator<P, C> {
    pub(crate) lhs: Vec<TestDataSample<P, C>>,
    pub(crate) rhs: Vec<TestDataSample<P, C>>,
    deterministic_seeder: DeterministicSeeder<DefaultRandomGenerator>,
    seed: Seed,
    cks: RadixClientKey,
    op_counter: usize,
}

impl<
        P: RadixEncryptable<Output = C> + DecomposableInto<u64> + CastFrom<u128> + std::fmt::Display,
        C: IntegerCiphertext,
    > RandomOpSequenceDataGenerator<P, C>
{
    fn new(total_num_ops: usize, cks: &RadixClientKey) -> Self {
        let mut rng = rand::thread_rng();

        let seed: u128 = rng.gen();
        Self::new_with_seed(total_num_ops, Seed(seed), cks)
    }

    fn make_data_sample_vector(
        deterministic_seeder: &mut DeterministicSeeder<DefaultRandomGenerator>,
        total_num_ops: usize,
        cks: &RadixClientKey,
    ) -> Vec<TestDataSample<P, C>> {
        (0..total_num_ops)
            .map(|_| {
                let plain: P = P::cast_from(deterministic_seeder.seed().0);
                let cipher: C = plain.encrypt(cks);
                TestDataSample {
                    p: plain,
                    c: cipher,
                    producer: ("encrypt".to_string(), 0),
                }
            }) // Generate random i64 values and encrypt them
            .collect()
    }
    fn new_with_seed(total_num_ops: usize, seed: Seed, cks: &RadixClientKey) -> Self {
        let mut deterministic_seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(seed);

        Self {
            lhs: Self::make_data_sample_vector(&mut deterministic_seeder, total_num_ops, cks),
            rhs: Self::make_data_sample_vector(&mut deterministic_seeder, total_num_ops, cks),
            deterministic_seeder,
            seed,
            cks: cks.clone(),
            op_counter: 0,
        }
    }

    fn get_seed(&self) -> Seed {
        self.seed
    }

    fn gen_op_index(&mut self) -> (usize, usize) {
        let op_count = self.op_counter;
        self.op_counter += 1;
        (
            self.deterministic_seeder.seed().0 as usize % self.lhs.len(),
            op_count,
        )
    }
    fn gen_op_operands(
        &mut self,
        op_idx: usize,
        op_name: &str,
    ) -> (TestDataSample<P, C>, TestDataSample<P, C>) {
        let i = self.deterministic_seeder.seed().0 as usize % self.lhs.len();
        let j = self.deterministic_seeder.seed().0 as usize % self.rhs.len();

        let input_degrees_left: Vec<u64> =
            self.lhs[i].c.blocks().iter().map(|b| b.degree.0).collect();
        let input_degrees_right: Vec<u64> =
            self.rhs[j].c.blocks().iter().map(|b| b.degree.0).collect();

        println!("{op_idx}: Start {op_name} lhs[{i}]={} deg={input_degrees_left:?} (prod: {}:{}), rhs[{j}]={} deg={input_degrees_right:?} (prod: {}:{})",
            self.lhs[i].p, self.lhs[i].producer.1, self.lhs[i].producer.0, self.rhs[j].p, self.rhs[j].producer.1, self.rhs[j].producer.0,
        );

        (self.lhs[i].clone(), self.rhs[j].clone())
    }

    fn gen_op_single_operand(&mut self, op_idx: usize, op_name: &str) -> TestDataSample<P, C> {
        let side = self.deterministic_seeder.seed().0 % 2;

        let i = self.deterministic_seeder.seed().0 as usize % self.lhs.len();
        let j = self.deterministic_seeder.seed().0 as usize % self.rhs.len();

        let (operand, side_str, operand_idx) = if side == 0 {
            (&self.lhs[i], "left", i)
        } else {
            (&self.rhs[j], "right", j)
        };

        let input_degrees: Vec<u64> = operand.c.blocks().iter().map(|b| b.degree.0).collect();

        println!(
            "{op_idx}: Start {op_name} {side_str}[{operand_idx}]={} deg={input_degrees:?} (prod: {}:{})",
            operand.p,
            operand.producer.1, operand.producer.0
        );

        operand.clone()
    }

    fn put_op_result_random_side(
        &mut self,
        clear: P,
        encrypted: &C,
        op_name: &String,
        op_index: usize,
    ) {
        let output_degrees: Vec<u64> = encrypted.blocks().iter().map(|b| b.degree.0).collect();

        let side = self.deterministic_seeder.seed().0 % 2;

        let (out, side_str) = if side == 0 {
            (&mut self.lhs, "left")
        } else {
            (&mut self.rhs, "right")
        };

        let outindex = self.deterministic_seeder.seed().0 as usize % out.len();

        println!("{op_index}: Executed {op_name}: out degrees {output_degrees:?}. Writing result to {side_str}:{outindex}");

        out[outindex] = TestDataSample {
            p: clear,
            c: encrypted.clone(),
            producer: (op_name.clone(), op_index),
        };
    }

    fn gen_encrypted_bool(&mut self) -> (bool, BooleanBlock) {
        let val = self.deterministic_seeder.seed().0 % 2;
        (val == 1, self.cks.encrypt_bool(val == 1))
    }
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn sanity_check_op_sequence_result_u64(
    op_index: usize,
    fn_name: &str,
    fn_index: usize,
    res: &RadixCiphertext,
    res1: &RadixCiphertext,
    decrypted: u64,
    expected: u64,
    lhs_p: u64,
    rhs_p: u64,
) {
    // Check carries are empty and noise level is lower or equal to nominal
    assert!(
        res.block_carries_are_empty(),
        "{op_index}: Non empty carries on op {fn_name}",
    );
    res.blocks.iter().enumerate().for_each(|(k, b)| {
        assert!(
            b.noise_level() <= NoiseLevel::NOMINAL,
            "{op_index}: Noise level greater than nominal value on op {fn_name} for block {k}",
        )
    });
    // Determinism check
    assert_eq!(
        res, res1,
        "{op_index}: Determinism check failed on binary op {fn_name} with clear inputs {lhs_p} and {rhs_p}.",
    );
    // Correctness check
    assert_eq!(
        decrypted, expected,
        "{op_index}: Invalid result on binary op {fn_name} with clear inputs {lhs_p} and {rhs_p} at iteration {fn_index}.",
    );
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn sanity_check_op_sequence_result_bool<P: std::fmt::Display>(
    op_index: usize,
    fn_name: &str,
    fn_index: usize,
    res: &BooleanBlock,
    res1: &BooleanBlock,
    decrypted: bool,
    expected: bool,
    lhs_p: P,
    rhs_p: P,
) {
    assert!(
        res.0.noise_level() <= NoiseLevel::NOMINAL,
        "{op_index}: Noise level greater than nominal value on op {fn_name}",
    );
    // Determinism check
    assert_eq!(
        res, res1,
        "{op_index}: Determinism check failed on binary op {fn_name} with clear inputs {lhs_p} and {rhs_p}.",
    );
    // Correctness check
    assert_eq!(
        decrypted, expected,
        "{op_index}: Invalid result on binary op {fn_name} with clear inputs {lhs_p} and {rhs_p} at iteration {fn_index}.",
    );
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn sanity_check_op_sequence_result_i64(
    op_index: usize,
    fn_name: &str,
    fn_index: usize,
    res: &SignedRadixCiphertext,
    res1: &SignedRadixCiphertext,
    decrypted: i64,
    expected: i64,
    lhs_p: i64,
    rhs_p: i64,
) {
    // Check carries are empty and noise level is lower or equal to nominal
    assert!(
        res.block_carries_are_empty(),
        "{op_index}: Non empty carries on op {fn_name}",
    );
    res.blocks.iter().enumerate().for_each(|(k, b)| {
        assert!(
            b.noise_level() <= NoiseLevel::NOMINAL,
            "{op_index}: Noise level greater than nominal value on op {fn_name} for block {k}",
        )
    });
    // Determinism check
    assert_eq!(
        res, res1,
        "{op_index}: Determinism check failed on binary op {fn_name} with clear inputs {lhs_p} and {rhs_p}.",
    );
    // Correctness check
    assert_eq!(
        decrypted, expected,
        "{op_index}: Invalid result on binary op {fn_name} with clear inputs {lhs_p} and {rhs_p} at iteration {fn_index}.",
    );
}
