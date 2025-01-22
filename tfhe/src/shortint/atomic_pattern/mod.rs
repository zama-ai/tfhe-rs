use serde::{Deserialize, Serialize};
use tfhe_versionable::Versionize;

use super::backward_compatibility::atomic_pattern::AtomicPatternKindVersions;
use super::PBSOrder;

/// A choice of atomic pattern
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Versionize)]
#[versionize(AtomicPatternKindVersions)]
pub enum AtomicPatternKind {
    /// The classical TFHE Atomic Pattern, as described here: <https://eprint.iacr.org/2021/091.pdf>
    ///
    /// `n linear operations + Keyswitch + Bootstrap`, or `n linear operations +  Bootstrap +
    /// Keyswitch` based on the [`PBSOrder`].
    Classical(PBSOrder),
}
