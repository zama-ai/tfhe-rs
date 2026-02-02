use super::bench_wait::*;
use rand::distributions::Standard;
use rand::prelude::*;
use std::marker::PhantomData;
use tfhe::prelude::*;
use tfhe::{ClientKey, FheBool};

pub trait BenchmarkOp<FheType> {
    type Output: BenchWait;
    type Inputs: Sync + Send;

    /// Setup the encrypted inputs for the operation
    fn setup_inputs(&self, client_key: &ClientKey, rng: &mut ThreadRng) -> Self::Inputs;

    /// Execute the operation with the inputs
    fn execute(&self, inputs: &Self::Inputs) -> Self::Output;
}

pub struct UnaryOp<F, EncryptType> {
    pub func: F,
    pub _encrypt: PhantomData<EncryptType>,
}

impl<FheType, F, R, EncryptType> BenchmarkOp<FheType> for UnaryOp<F, EncryptType>
where
    F: Fn(&FheType) -> R,
    R: BenchWait,
    FheType: FheEncrypt<EncryptType, ClientKey> + Send + Sync,
    Standard: Distribution<EncryptType>,
{
    type Output = R;
    type Inputs = FheType;

    fn setup_inputs(&self, client_key: &ClientKey, rng: &mut ThreadRng) -> Self::Inputs {
        FheType::encrypt(rng.gen(), client_key)
    }

    fn execute(&self, inputs: &Self::Inputs) -> Self::Output {
        (self.func)(inputs)
    }
}

pub struct ScalarBinaryOp<F, G, EncryptType> {
    pub func: F,
    pub rng_function: G,
    pub _encrypt: PhantomData<EncryptType>,
}

impl<FheType, F, R, G, T, EncryptType> BenchmarkOp<FheType> for ScalarBinaryOp<F, G, EncryptType>
where
    F: Fn(&FheType, &T) -> R,
    R: BenchWait,
    G: Fn() -> T,
    FheType: FheEncrypt<EncryptType, ClientKey> + Sync + Send,
    Standard: Distribution<EncryptType>,
    T: Sync + Send,
{
    type Output = R;
    type Inputs = (FheType, T);

    fn setup_inputs(&self, client_key: &ClientKey, rng: &mut ThreadRng) -> Self::Inputs {
        (
            FheType::encrypt(rng.gen(), client_key),
            (self.rng_function)(),
        )
    }

    fn execute(&self, inputs: &Self::Inputs) -> Self::Output {
        (self.func)(&inputs.0, &inputs.1)
    }
}

pub struct BinaryOp<F, EncryptLhsType, EncryptRhsType, FheRhsType> {
    pub func: F,
    pub _encrypt_lhs: PhantomData<EncryptLhsType>,
    pub _encrypt_rhs: PhantomData<EncryptRhsType>,
    pub _rhs_type: PhantomData<FheRhsType>,
}

impl<FheType, FheRhsType, F, R, EncryptLhsType, EncryptRhsType> BenchmarkOp<FheType>
    for BinaryOp<F, EncryptLhsType, EncryptRhsType, FheRhsType>
where
    F: Fn(&FheType, &FheRhsType) -> R,
    R: BenchWait,
    FheType: FheEncrypt<EncryptLhsType, ClientKey> + Sync + Send,
    FheRhsType: FheEncrypt<EncryptRhsType, ClientKey> + Sync + Send,
    Standard: Distribution<EncryptLhsType>,
    Standard: Distribution<EncryptRhsType>,
{
    type Output = R;
    type Inputs = (FheType, FheRhsType);

    fn setup_inputs(&self, client_key: &ClientKey, rng: &mut ThreadRng) -> Self::Inputs {
        (
            FheType::encrypt(rng.gen(), client_key),
            FheRhsType::encrypt(rng.gen(), client_key),
        )
    }

    fn execute(&self, inputs: &Self::Inputs) -> Self::Output {
        (self.func)(&inputs.0, &inputs.1)
    }
}

pub struct TernaryOp<F, EncryptType> {
    pub func: F,
    pub _encrypt: PhantomData<EncryptType>,
}

impl<FheType, F, R, EncryptType> BenchmarkOp<FheType> for TernaryOp<F, EncryptType>
where
    F: Fn(&FheBool, &FheType, &FheType) -> R,
    R: BenchWait,
    FheType: FheEncrypt<EncryptType, ClientKey> + Sync + Send,
    Standard: Distribution<EncryptType>,
{
    type Output = R;
    type Inputs = (FheBool, FheType, FheType);

    fn setup_inputs(&self, client_key: &ClientKey, rng: &mut ThreadRng) -> Self::Inputs {
        (
            FheBool::encrypt(rng.gen::<bool>(), client_key),
            FheType::encrypt(rng.gen(), client_key),
            FheType::encrypt(rng.gen(), client_key),
        )
    }

    fn execute(&self, inputs: &Self::Inputs) -> Self::Output {
        (self.func)(&inputs.0, &inputs.1, &inputs.2)
    }
}

pub struct ArrayOp<F, EncryptType> {
    pub func: F,
    pub array_size: usize,
    pub _encrypt: PhantomData<EncryptType>,
}

impl<FheType, F, EncryptType> BenchmarkOp<FheType> for ArrayOp<F, EncryptType>
where
    F: for<'a> Fn(std::slice::Iter<'a, FheType>) -> FheType,
    FheType: FheEncrypt<EncryptType, ClientKey> + Clone + BenchWait + Sync + Send,
    Standard: Distribution<EncryptType>,
{
    type Output = FheType;
    type Inputs = Vec<FheType>;

    fn setup_inputs(&self, client_key: &ClientKey, rng: &mut ThreadRng) -> Self::Inputs {
        (0..self.array_size)
            .map(|_| FheType::encrypt(rng.gen(), client_key))
            .collect()
    }

    fn execute(&self, inputs: &Self::Inputs) -> Self::Output {
        (self.func)(inputs.iter())
    }
}
