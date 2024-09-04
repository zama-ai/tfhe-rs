use tfhe_versionable::{Upgrade, Version, VersionsDispatch};

use crate::core_crypto::prelude::{Container, SeededLweKeyswitchKey, UnsignedInteger};

#[derive(Version)]
pub struct UnsupportedSeededLweKeyswitchKeyV0;

impl<Scalar: UnsignedInteger, C: Container<Element = Scalar>> Upgrade<SeededLweKeyswitchKey<C>>
    for UnsupportedSeededLweKeyswitchKeyV0
{
    type Error = crate::Error;

    fn upgrade(self) -> Result<SeededLweKeyswitchKey<C>, Self::Error> {
        Err(crate::Error::new(
            "Unable to load SeededLweKeyswitchKey, \
            this format is UnsupportedSeededLweKeyswitchKeyV0 by this TFHE-rs version."
                .to_string(),
        ))
    }
}

#[derive(VersionsDispatch)]
pub enum SeededLweKeyswitchKeyVersions<C: Container>
where
    C::Element: UnsignedInteger,
{
    V0(UnsupportedSeededLweKeyswitchKeyV0),
    V1(SeededLweKeyswitchKey<C>),
}
