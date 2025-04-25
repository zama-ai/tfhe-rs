use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

use super::backward_compatibility::atomic_pattern::AtomicPatternKindVersions;
use super::PBSOrder;

/// A choice of atomic pattern
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Versionize)]
#[versionize(AtomicPatternKindVersions)]
pub enum AtomicPatternKind {
    /// The Standard TFHE Atomic Pattern, that correspond to what was done before TFHE-rs 1.2.
    ///
    /// This is actually a "meta" atomic pattern, that can be configured in several ways:
    /// - PBS order (KS -> Bootstrap or Bootstrap -> Keyswitch)
    /// - PBS kind (classic or multibit)
    Standard(PBSOrder),
}
