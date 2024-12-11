use tfhe_versionable::VersionsDispatch;

use crate::prelude::{Container, PolynomialList};

#[derive(VersionsDispatch)]
pub enum PolynomialListVersions<C: Container> {
    V0(PolynomialList<C>),
}
