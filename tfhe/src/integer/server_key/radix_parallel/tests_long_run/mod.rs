use rand::Rng;
use tfhe_csprng::generators::DefaultRandomGenerator;
use tfhe_csprng::seeders::Seed;
use crate::core_crypto::commons::generators::DeterministicSeeder;
use crate::integer::RadixClientKey;
use crate::integer::{RadixCiphertext, SignedRadixCiphertext};
use crate::integer::block_decomposition::DecomposableInto;
use tfhe_csprng::seeders::Seeder;
use crate::core_crypto::prelude::CastFrom;
use crate::integer::IntegerCiphertext;

pub(crate) mod test_erc20;
pub(crate) mod test_random_op_sequence;
pub(crate) mod test_signed_erc20;
pub(crate) mod test_signed_random_op_sequence;
pub(crate) const NB_CTXT_LONG_RUN: usize = 32;
pub(crate) const NB_TESTS_LONG_RUN: usize = 20000;
pub(crate) const NB_TESTS_LONG_RUN_MINIMAL: usize = 200;

pub(crate) fn get_long_test_iterations() -> usize {
    static SINGLE_KEY_DEBUG: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

    let is_long_tests_minimal = *SINGLE_KEY_DEBUG.get_or_init(|| {
        std::env::var("TFHE_RS_TESTS_LONG_TESTS_MINIMAL")
            .is_ok_and(|val| val.to_uppercase() == "TRUE")
    });

    if is_long_tests_minimal {
        NB_TESTS_LONG_RUN_MINIMAL
    } else {
        NB_TESTS_LONG_RUN
    }
}

pub(crate) struct TestDataSample<P, C> {
    pub(crate) p: P,
    pub(crate) c: C,
    pub(crate) producer: String,
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

/*impl EncryptSample for bool {
    fn encrypt(&self, cks: &RadixClientKey) -> RadixCiphertext {
        cks.encrypt_bool(*self)
    }
}*/

struct RandomOpSequenceDataGenerator<P, C> {
    pub(crate) lhs: Vec<TestDataSample<P, C>>,
    pub(crate) rhs: Vec<TestDataSample<P, C>>,
    deterministic_seeder: DeterministicSeeder::<DefaultRandomGenerator>,
    seed: Seed,
    cks: RadixClientKey,
    op_counter: usize,
}

impl<P:RadixEncryptable<Output = C> + DecomposableInto<u64> + CastFrom<u128>, C:IntegerCiphertext> RandomOpSequenceDataGenerator<P, C> {
    fn new(total_num_ops: usize, cks: &RadixClientKey) -> Self {
        let mut rng = rand::thread_rng();

        let seed: u128 = rng.gen();
        Self::new_with_seed(total_num_ops, Seed(seed), cks)
    }

    fn make_data_sample_vector(deterministic_seeder: &mut DeterministicSeeder<DefaultRandomGenerator>, total_num_ops: usize, cks: &RadixClientKey) -> Vec<TestDataSample<P, C>> {
        (0..total_num_ops)
            .map(|_| {
                let plain: P = P::cast_from(deterministic_seeder.seed().0);
                let cipher: C = plain.encrypt(&cks);
                TestDataSample {
                    p: plain,
                    c: cipher,
                    producer: "encrypt".to_string(),
                }
            }) // Generate random i64 values and encrypt them
            .collect()
    }
    fn new_with_seed(total_num_ops: usize, seed: Seed, cks: &RadixClientKey) -> Self {
        let mut deterministic_seeder = DeterministicSeeder::<DefaultRandomGenerator>::new(seed);

        RandomOpSequenceDataGenerator {
            lhs: Self::make_data_sample_vector(&mut deterministic_seeder, total_num_ops, cks),
            rhs: Self::make_data_sample_vector(&mut deterministic_seeder, total_num_ops, cks),
            deterministic_seeder,
            seed,
            cks: RadixClientKey::from(cks.clone()),
            op_counter: 0
        }
    }

    fn get_seed(&self) -> Seed {
        self.seed
    }

    fn gen_op_index(&mut self) -> (usize, usize) {
        let op_count = self.op_counter;
        self.op_counter += 1;
        (self.deterministic_seeder.seed().0 as usize % self.lhs.len(), op_count)
    }
    fn gen_op_operands(&mut self, op_idx: usize) -> (&TestDataSample<P, C>, &TestDataSample<P, C>) {
        let i = self.deterministic_seeder.seed().0 as usize % self.lhs.len();
        let j = self.deterministic_seeder.seed().0 as usize % self.rhs.len();

        let input_degrees_left: Vec<u64> =
            self.lhs[i].c.blocks().iter().map(|b| b.degree.0).collect();
        let input_degrees_right: Vec<u64> =
            self.rhs[j].c.blocks().iter().map(|b| b.degree.0).collect();

        println!("{op_idx}: lhs {i} deg={input_degrees_left:?}, rhs {j} deg={input_degrees_right:?}");

        (&self.lhs[i], &self.rhs[j])
    }

    fn put_op_result_random_side(&mut self, clear: P, encrypted: C, op_name: &String, op_index: usize) {
        let output_degrees: Vec<u64> =
            encrypted.blocks().iter().map(|b| b.degree.0).collect();

        println!("{op_index}: Executed {op_name}: out degrees {output_degrees:?}");

        let side = self.deterministic_seeder.seed().0 % 2;

        let out = if side == 0 {
            &mut self.lhs
        } else {
            &mut self.rhs
        };

        let outindex = self.deterministic_seeder.seed().0 as usize % out.len();

        out[outindex] = TestDataSample { p: clear, c: encrypted.clone(), producer: op_name.clone() };
    }
}

