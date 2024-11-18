use super::*;
mod dop_macro;
mod fmt;
use super::pbs::{Pbs, PbsLut};
pub use fmt::DOp as FmtDOp;

use deku::DekuContainerWrite;
use rand::rngs::StdRng;
use rand::Rng;
use serde::{Deserialize, Serialize};

use strum::IntoEnumIterator;
use strum_macros::{EnumDiscriminants, EnumIter, EnumString};

use crate::{arith_dop, arith_mf_dop, arith_msg_dop, memld_dop, memst_dop, pbs_dop, sync_dop};

/// Use enum dispatch for ease of writing and code reabability.
/// This enable to implement the targeted trait for each instruction and hide the matching logic
/// over the enum. It's not the best solution but it enhance the code locality.
/// As a side effect, this required to have all asm defined in the same scope, this is way each
/// operaton implementation is prepend with "DOp"
#[enum_dispatch]
#[derive(Debug, Clone, EnumIter, EnumDiscriminants)]
#[strum_discriminants(
    name(DOpName),
    derive(
        Serialize,
        Deserialize,
        EnumIter,
        Hash,
        strum_macros::Display,
        EnumString
    )
)]
#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub enum DOp {
    ADD(DOpAdd),
    SUB(DOpSub),
    MAC(DOpMac),

    ADDS(DOpAdds),
    SUBS(DOpSubs),
    SSUB(DOpSsub),
    MULS(DOpMuls),

    LD(DOpLd),
    TLDA(DOpTlda),
    TLDB(DOpTldb),
    TLDH(DOpTldh),

    ST(DOpSt),
    TSTD(DOpTstd),
    TSTH(DOpTsth),

    PBS(DOpPbs),
    #[allow(non_camel_case_types)]
    PBS_F(DOpPbsF),

    SYNC(DOpSync),
}

/// Use for easy convertion between CLI arg and real IOp
impl From<DOpName> for DOp {
    fn from(value: DOpName) -> Self {
        let iop = Self::iter().find(|op| op.name() == value.to_string());
        iop.unwrap()
    }
}

// With help of macro define encoding/decoding for DOp
// Arith
arith_dop!("ADD");
arith_dop!("SUB");
arith_mf_dop!("MAC");
// ArithMsg
arith_msg_dop!("ADDS");
arith_msg_dop!("SUBS");
arith_msg_dop!("SSUB");
arith_msg_dop!("MULS");
//LD & Template
memld_dop!("LD", None::<MemOrigin>);
memld_dop!("TLDA", Some(MemOrigin::SrcA));
memld_dop!("TLDB", Some(MemOrigin::SrcB));
memld_dop!("TLDH", Some(MemOrigin::Heap));

//ST & Template
memst_dop!("ST", None::<MemOrigin>);
memst_dop!("TSTD", Some(MemOrigin::Dst));
memst_dop!("TSTH", Some(MemOrigin::Heap));
//PBS
pbs_dop!("PBS");
pbs_dop!("PBS_F");
// Sync
sync_dop!("SYNC");
