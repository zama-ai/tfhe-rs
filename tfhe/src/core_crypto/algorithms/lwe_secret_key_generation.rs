use crate::core_crypto::commons::crypto::secret::generators::SecretRandomGenerator;
use crate::core_crypto::commons::math::random::{
    ByteRandomGenerator, RandomGenerable, UniformBinary,
};
use crate::core_crypto::commons::numeric::Numeric;
use crate::core_crypto::commons::traits::ContainerMut;
use crate::core_crypto::entities::lwe_secret_key::{LweSecretKey, LweSecretKeyBase};
use crate::core_crypto::specification::parameters::LweDimension;

pub fn allocate_and_generate_new_binary_lwe_secret_key<Scalar, Gen>(
    lwe_dimension: LweDimension,
    generator: &mut SecretRandomGenerator<Gen>,
) -> LweSecretKey<Scalar>
where
    Scalar: RandomGenerable<UniformBinary> + Numeric,
    Gen: ByteRandomGenerator,
{
    let mut lwe_secret_key = LweSecretKey::new(Scalar::ZERO, lwe_dimension);

    generate_binary_lwe_secret_key(&mut lwe_secret_key, generator);

    lwe_secret_key
}

pub fn generate_binary_lwe_secret_key<Scalar, InCont, Gen>(
    lwe_secret_key: &mut LweSecretKeyBase<InCont>,
    generator: &mut SecretRandomGenerator<Gen>,
) where
    Scalar: RandomGenerable<UniformBinary>,
    InCont: ContainerMut<Element = Scalar>,
    Gen: ByteRandomGenerator,
{
    generator.fill_slice_with_random_uniform_binary(lwe_secret_key.as_mut())
}
