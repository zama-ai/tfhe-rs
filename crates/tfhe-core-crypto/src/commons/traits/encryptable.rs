use crate::commons::math::random::{Distribution, RandomGenerable};
use crate::commons::numeric::UnsignedInteger;

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
