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

pub struct UnaryOp<FheType, R, EncryptType> {
    pub func: fn(&FheType) -> R,
    pub _encrypt: PhantomData<EncryptType>,
}

impl<FheType, R, EncryptType> BenchmarkOp<FheType> for UnaryOp<FheType, R, EncryptType>
where
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

pub struct ScalarBinaryOp<FheType, T, R, EncryptType> {
    pub func: fn(&FheType, &T) -> R,
    pub rng_function: fn() -> T,
    pub _encrypt: PhantomData<EncryptType>,
}

impl<FheType, R, T, EncryptType> BenchmarkOp<FheType> for ScalarBinaryOp<FheType, T, R, EncryptType>
where
    R: BenchWait,
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

pub struct BinaryOp<FheType, R, EncryptLhsType, EncryptRhsType, FheRhsType> {
    pub func: fn(&FheType, &FheRhsType) -> R,
    pub _encrypt_lhs: PhantomData<EncryptLhsType>,
    pub _encrypt_rhs: PhantomData<EncryptRhsType>,
    pub _rhs_type: PhantomData<FheRhsType>,
}

impl<FheType, FheRhsType, R, EncryptLhsType, EncryptRhsType> BenchmarkOp<FheType>
    for BinaryOp<FheType, R, EncryptLhsType, EncryptRhsType, FheRhsType>
where
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

pub struct TernaryOp<FheType, R, EncryptType> {
    pub func: fn(&FheBool, &FheType, &FheType) -> R,
    pub _encrypt: PhantomData<EncryptType>,
}

impl<FheType, R, EncryptType> BenchmarkOp<FheType> for TernaryOp<FheType, R, EncryptType>
where
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

pub struct ArrayOp<FheType, EncryptType> {
    pub func: fn(std::slice::Iter<'_, FheType>) -> FheType,
    pub array_size: usize,
    pub _encrypt: PhantomData<EncryptType>,
}

impl<FheType, EncryptType> BenchmarkOp<FheType> for ArrayOp<FheType, EncryptType>
where
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
