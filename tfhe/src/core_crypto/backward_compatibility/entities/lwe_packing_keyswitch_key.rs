use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

use crate::core_crypto::prelude::{
    CiphertextModulus, Container, ContainerMut, ContiguousEntityContainerMut, DecompositionBaseLog,
    DecompositionLevelCount, GlweSize, LwePackingKeyswitchKey, PolynomialSize, UnsignedInteger,
};

#[derive(Version)]
pub struct LwePackingKeyswitchKeyV0<C: Container>
where
    C::Element: UnsignedInteger,
{
    data: C,
    decomp_base_log: DecompositionBaseLog,
    decomp_level_count: DecompositionLevelCount,
    output_glwe_size: GlweSize,
    output_polynomial_size: PolynomialSize,
    ciphertext_modulus: CiphertextModulus<C::Element>,
}

impl<Scalar: UnsignedInteger, C: ContainerMut<Element = Scalar>> Upgrade<LwePackingKeyswitchKey<C>>
    for LwePackingKeyswitchKeyV0<C>
{
    type Error = std::convert::Infallible;

    fn upgrade(self) -> Result<LwePackingKeyswitchKey<C>, Self::Error> {
        let Self {
            data,
            decomp_base_log,
            decomp_level_count,
            output_glwe_size,
            output_polynomial_size,
            ciphertext_modulus,
        } = self;
        let mut new_pksk = LwePackingKeyswitchKey::from_container(
            data,
            decomp_base_log,
            decomp_level_count,
            output_glwe_size,
            output_polynomial_size,
            ciphertext_modulus,
        );

        // Invert levels
        for mut pksk_block in new_pksk.iter_mut() {
            pksk_block.reverse();
        }

        Ok(new_pksk)
    }
}

#[derive(VersionsDispatch)]
pub enum LwePackingKeyswitchKeyVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(LwePackingKeyswitchKeyV0<C>),
    V1(LwePackingKeyswitchKey<C>),
}
