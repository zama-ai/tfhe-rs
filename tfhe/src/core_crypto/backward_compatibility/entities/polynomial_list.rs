use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Container, PolynomialList};

#[derive(VersionsDispatch)]
pub enum PolynomialListVersions<C: Container> {
    V0(PolynomialList<C>),
}
