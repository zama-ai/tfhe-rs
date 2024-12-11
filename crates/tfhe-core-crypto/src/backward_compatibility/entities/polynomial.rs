use tfhe_versionable::VersionsDispatch;

use crate::prelude::{Container, Polynomial};

#[derive(VersionsDispatch)]
pub enum PolynomialVersions<C: Container> {
    V0(Polynomial<C>),
}
