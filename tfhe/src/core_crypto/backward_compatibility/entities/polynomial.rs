use tfhe_versionable::VersionsDispatch;

use crate::core_crypto::prelude::{Container, Polynomial};

#[derive(VersionsDispatch)]
pub enum PolynomialVersions<C: Container> {
    V0(Polynomial<C>),
}
