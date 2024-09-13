use super::*;
mod fmt;
mod iop_macro;
pub use fmt::IOp as FmtIOp;

use deku::DekuContainerWrite;

use rand::rngs::StdRng;
use rand::Rng;

use strum::IntoEnumIterator;
use strum_macros::{Display, EnumDiscriminants, EnumIter, EnumString};

use crate::{ct_ct_iop, ct_imm_iop};

// Parsing error
#[derive(Error, Debug, Clone)]
pub enum ArgError {
    #[error("Invalid arguments number: {self:?}[exp, get]")]
    InvalidNumber(usize, usize),
    #[error("Invalid arguments: {self:?}[exp, get]")]
    InvalidField(String, Arg),
}

/// Use enum dispatch for ease of writing and code reabability.
/// This enable to implement the targeted trait for each instruction and hide the matching logic
/// over the enum. It's not the best solution but it enhance the code locality.
/// As a side effect, this required to have all asm defined in the same scope, this is way each
/// operaton implementation is prepend with "IOp"
#[enum_dispatch]
#[derive(Debug, Clone, EnumIter, EnumDiscriminants)]
#[strum_discriminants(
    name(IOpName),
    derive(Serialize, Deserialize, EnumIter, EnumString, Display)
)]
#[allow(non_camel_case_types)]
pub enum IOp {
    ADDS(IOpAdds),
    SUBS(IOpSubs),
    SSUB(IOpSsub),
    MULS(IOpMuls),
    ADD(IOpAdd),
    SUB(IOpSub),
    MUL(IOpMul),

    #[allow(non_camel_case_types)]
    BW_AND(IOpBwAnd),
    #[allow(non_camel_case_types)]
    BW_OR(IOpBwOr),
    #[allow(non_camel_case_types)]
    BW_XOR(IOpBwXor),

    #[allow(non_camel_case_types)]
    CMP_GT(IOpCmpGt),
    #[allow(non_camel_case_types)]
    CMP_GTE(IOpCmpGte),
    #[allow(non_camel_case_types)]
    CMP_LT(IOpCmpLt),
    #[allow(non_camel_case_types)]
    CMP_LTE(IOpCmpLte),
    #[allow(non_camel_case_types)]
    CMP_EQ(IOpCmpEq),
    #[allow(non_camel_case_types)]
    CMP_NEQ(IOpCmpNeq),

    #[allow(non_camel_case_types)]
    CUST_0(IOpCust0),
    #[allow(non_camel_case_types)]
    CUST_1(IOpCust1),
    #[allow(non_camel_case_types)]
    CUST_2(IOpCust2),
    #[allow(non_camel_case_types)]
    CUST_3(IOpCust3),
    #[allow(non_camel_case_types)]
    CUST_4(IOpCust4),
    #[allow(non_camel_case_types)]
    CUST_5(IOpCust5),
    #[allow(non_camel_case_types)]
    CUST_6(IOpCust6),
    #[allow(non_camel_case_types)]
    CUST_7(IOpCust7),
    #[allow(non_camel_case_types)]
    CUST_8(IOpCust8),
    #[allow(non_camel_case_types)]
    CUST_9(IOpCust9),
    #[allow(non_camel_case_types)]
    CUST_A(IOpCustA),
    #[allow(non_camel_case_types)]
    CUST_B(IOpCustB),
    #[allow(non_camel_case_types)]
    CUST_C(IOpCustC),
    #[allow(non_camel_case_types)]
    CUST_D(IOpCustD),
    #[allow(non_camel_case_types)]
    CUST_E(IOpCustE),
    #[allow(non_camel_case_types)]
    CUST_F(IOpCustF),

    #[allow(non_camel_case_types)]
    CUSTI_0(IOpCusti0),
    #[allow(non_camel_case_types)]
    CUSTI_1(IOpCusti1),
    #[allow(non_camel_case_types)]
    CUSTI_2(IOpCusti2),
    #[allow(non_camel_case_types)]
    CUSTI_3(IOpCusti3),
    #[allow(non_camel_case_types)]
    CUSTI_4(IOpCusti4),
    #[allow(non_camel_case_types)]
    CUSTI_5(IOpCusti5),
    #[allow(non_camel_case_types)]
    CUSTI_6(IOpCusti6),
    #[allow(non_camel_case_types)]
    CUSTI_7(IOpCusti7),
    #[allow(non_camel_case_types)]
    CUSTI_8(IOpCusti8),
    #[allow(non_camel_case_types)]
    CUSTI_9(IOpCusti9),
    #[allow(non_camel_case_types)]
    CUSTI_A(IOpCustiA),
    #[allow(non_camel_case_types)]
    CUSTI_B(IOpCustiB),
    #[allow(non_camel_case_types)]
    CUSTI_C(IOpCustiC),
    #[allow(non_camel_case_types)]
    CUSTI_D(IOpCustiD),
    #[allow(non_camel_case_types)]
    CUSTI_E(IOpCustiE),
    #[allow(non_camel_case_types)]
    CUSTI_F(IOpCustiF),
    #[allow(non_camel_case_types)]
    CTL_WR(IOpCtlWr),
    #[allow(non_camel_case_types)]
    CTL_RD(IOpCtlRd),
}

/// Use for easy convertion between CLI arg and real IOp
impl From<IOpName> for IOp {
    fn from(value: IOpName) -> Self {
        let iop = Self::iter().find(|op| op.name() == value.to_string());
        iop.unwrap()
    }
}

// With help of macro define encoding/decoding for IOp
// IOp have mainly two format ct.ct and ct.scalar
ct_imm_iop!("ADDS");
ct_imm_iop!("SUBS");
ct_imm_iop!("SSUB");
ct_imm_iop!("MULS");

ct_ct_iop!("ADD");
ct_ct_iop!("SUB");
ct_ct_iop!("MUL");

ct_ct_iop!("BW_AND");
ct_ct_iop!("BW_OR");
ct_ct_iop!("BW_XOR");

ct_ct_iop!("CMP_GT");
ct_ct_iop!("CMP_GTE");
ct_ct_iop!("CMP_LT");
ct_ct_iop!("CMP_LTE");
ct_ct_iop!("CMP_EQ");
ct_ct_iop!("CMP_NEQ");

ct_ct_iop!("CUST_0");
ct_ct_iop!("CUST_1");
ct_ct_iop!("CUST_2");
ct_ct_iop!("CUST_3");
ct_ct_iop!("CUST_4");
ct_ct_iop!("CUST_5");
ct_ct_iop!("CUST_6");
ct_ct_iop!("CUST_7");
ct_ct_iop!("CUST_8");
ct_ct_iop!("CUST_9");
ct_ct_iop!("CUST_A");
ct_ct_iop!("CUST_B");
ct_ct_iop!("CUST_C");
ct_ct_iop!("CUST_D");
ct_ct_iop!("CUST_E");
ct_ct_iop!("CUST_F");

ct_imm_iop!("CUSTI_0");
ct_imm_iop!("CUSTI_1");
ct_imm_iop!("CUSTI_2");
ct_imm_iop!("CUSTI_3");
ct_imm_iop!("CUSTI_4");
ct_imm_iop!("CUSTI_5");
ct_imm_iop!("CUSTI_6");
ct_imm_iop!("CUSTI_7");
ct_imm_iop!("CUSTI_8");
ct_imm_iop!("CUSTI_9");
ct_imm_iop!("CUSTI_A");
ct_imm_iop!("CUSTI_B");
ct_imm_iop!("CUSTI_C");
ct_imm_iop!("CUSTI_D");
ct_imm_iop!("CUSTI_E");
ct_imm_iop!("CUSTI_F");

ct_imm_iop!("CTL_WR");
ct_imm_iop!("CTL_RD");
