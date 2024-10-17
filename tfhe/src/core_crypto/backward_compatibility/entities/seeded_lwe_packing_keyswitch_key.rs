use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

use crate::core_crypto::prelude::{Container, SeededLwePackingKeyswitchKey, UnsignedInteger};

#[derive(Version)]
pub struct UnsupportedSeededLwePackingKeyswitchKeyV0;

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>>
    Upgrade<SeededLwePackingKeyswitchKey<C>> for UnsupportedSeededLwePackingKeyswitchKeyV0
{
    type Error = crate::Error;

    fn upgrade(self) -> Result<SeededLwePackingKeyswitchKey<C>, Self::Error> {
        Err(crate::Error::new(
            "Unable to load SeededLwePackingKeyswitchKey, \
            this format is unsupported by this TFHE-rs version."
                .to_string(),
        ))
    }
}

#[derive(VersionsDispatch)]
pub enum SeededLwePackingKeyswitchKeyVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(UnsupportedSeededLwePackingKeyswitchKeyV0),
    V1(SeededLwePackingKeyswitchKey<C>),
}
