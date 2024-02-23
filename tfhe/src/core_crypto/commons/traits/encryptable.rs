use crate::core_crypto::commons::math::random::{Distribution, RandomGenerable};
use crate::core_crypto::commons::numeric::UnsignedInteger;

pub trait Encryptable<MaskDistribution: Distribution, NoiseDistribution: Distribution>:
    UnsignedInteger
    + RandomGenerable<MaskDistribution, CustomModulus = Self>
    + RandomGenerable<NoiseDistribution, CustomModulus = Self>
{
}

impl<MaskDistribution: Distribution, NoiseDistribution: Distribution, T>
    Encryptable<MaskDistribution, NoiseDistribution> for T
where
    T: UnsignedInteger
        + RandomGenerable<MaskDistribution, CustomModulus = Self>
        + RandomGenerable<NoiseDistribution, CustomModulus = Self>,
{
}
