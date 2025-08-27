use hpu_asm::iop::*;
use tfhe_hpu_backend::prelude::*;

use crate::core_crypto::prelude::{CreateFrom, LweCiphertextOwned};
use crate::integer::{BooleanBlock, RadixCiphertext};
use crate::shortint::ciphertext::{Degree, NoiseLevel};
use crate::shortint::parameters::KeySwitch32PBSParameters;
use crate::shortint::{AtomicPatternKind, Ciphertext};

/// Simple wrapper over HpuVar
/// Add method to convert from/to cpu radix ciphertext
#[derive(Clone)]
pub struct HpuRadixCiphertext(pub(crate) HpuVarWrapped);

impl HpuRadixCiphertext {
    fn new(hpu_var: HpuVarWrapped) -> Self {
        Self(hpu_var)
    }

    /// Create a Hpu Radix ciphertext based on a Cpu one.
    ///
    /// No transfer with FPGA will occur until an operation on the HpuRadixCiphertext is requested
    pub fn from_radix_ciphertext(cpu_ct: &RadixCiphertext, device: &HpuDevice) -> Self {
        let params = device.params().clone();

        let hpu_ct = cpu_ct
            .blocks
            .iter()
            .map(|blk| HpuLweCiphertextOwned::create_from(blk.ct.as_view(), params.clone()))
            .collect::<Vec<_>>();

        Self(device.new_var_from(hpu_ct, VarMode::Native))
    }

    /// Create a Cpu radix ciphertext copy from a Hpu one.
    pub fn to_radix_ciphertext(&self) -> RadixCiphertext {
        // NB: We clone the inner part of HpuRadixCiphertext but it is not costly since
        // it's wrapped inside an Arc
        let hpu_ct = self.0.clone().into_ct();
        let cpu_ct = hpu_ct
            .into_iter()
            .map(|ct| {
                let pbs_p = KeySwitch32PBSParameters::from(ct.params());
                let cpu_ct = LweCiphertextOwned::from(ct.as_view());
                // Hpu output clean ciphertext without carry
                Ciphertext::new(
                    cpu_ct,
                    Degree::new(pbs_p.message_modulus.0 - 1),
                    NoiseLevel::NOMINAL,
                    pbs_p.message_modulus,
                    pbs_p.carry_modulus,
                    AtomicPatternKind::KeySwitch32,
                )
            })
            .collect::<Vec<_>>();
        RadixCiphertext { blocks: cpu_ct }
    }

    /// Create a Hpu boolean ciphertext based on a Cpu one.
    ///
    /// No transfer with FPGA will occur until an operation on the HpuRadixCiphertext is requested
    pub fn from_boolean_ciphertext(cpu_ct: &BooleanBlock, device: &HpuDevice) -> Self {
        let params = device.params().clone();

        let hpu_ct = vec![HpuLweCiphertextOwned::create_from(
            cpu_ct.0.ct.as_view(),
            params,
        )];
        Self(device.new_var_from(hpu_ct, VarMode::Bool))
    }

    /// Create a Cpu boolean block from a Hpu one
    ///
    /// # Panics
    ///
    /// This function panic if the underlying RadixCiphertext does not encrypt 0 or 1
    pub fn to_boolean_block(&self) -> BooleanBlock {
        assert!(
            self.0.is_boolean(),
            "Error try to extract boolean value from invalid ciphertext"
        );
        let mut boolean_ct = self
            .to_radix_ciphertext()
            .blocks
            .into_iter()
            .next()
            .unwrap();
        boolean_ct.degree = Degree::new(1);
        BooleanBlock::new_unchecked(boolean_ct)
    }
}

// Use to easily build HpuCmd exec request directly on HpuRadixCiphertext
impl std::ops::Deref for HpuRadixCiphertext {
    type Target = HpuVarWrapped;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl HpuRadixCiphertext {
    pub fn exec(
        proto: &IOpProto,
        opcode: IOpcode,
        rhs_ct: &[Self],
        rhs_imm: &[HpuImm],
    ) -> Vec<Self> {
        let rhs_var = rhs_ct.iter().map(|x| x.0.clone()).collect::<Vec<_>>();
        let res_var = HpuCmd::exec(proto, opcode, &rhs_var, rhs_imm);
        res_var.into_iter().map(Self::new).collect::<Vec<Self>>()
    }

    pub fn exec_assign(proto: &IOpProto, opcode: IOpcode, rhs_ct: &[Self], rhs_imm: &[HpuImm]) {
        let rhs_var = rhs_ct.iter().map(|x| x.0.clone()).collect::<Vec<_>>();
        HpuCmd::exec_assign(proto, opcode, &rhs_var, rhs_imm)
    }
}

// Below we map common Hpu operation to std::ops rust trait -------------------
#[macro_export]
/// Easily map an Hpu operation to std::ops rust trait
macro_rules! map_ct_ct {
    ($hpu_op: ident -> $rust_op: literal) => {
        ::paste::paste! {
            impl std::ops::[<$rust_op:camel>] for HpuRadixCiphertext {
                type Output = Self;

                fn [<$rust_op:lower>](self, rhs: Self) -> Self::Output {
                    let opcode = $hpu_op.opcode();
                    let proto = &$hpu_op.format().expect("Bind to std::ops a unspecified IOP").proto;

                    let res = HpuCmd::exec(proto, opcode, &[self.0, rhs.0], &[]);
                    Self::Output::new(res[0].clone())
                }
            }

            impl<'a> std::ops::[<$rust_op:camel>] for &'a HpuRadixCiphertext {
                type Output = HpuRadixCiphertext;

                fn [<$rust_op:lower>](self, rhs: Self) -> Self::Output {
                    let opcode = $hpu_op.opcode();
                    let proto = &$hpu_op.format().expect("Bind to std::ops a unspecified IOP").proto;

                    let res = HpuCmd::exec(proto, opcode, &[self.0.clone(), rhs.0.clone()], &[]);
                    Self::Output::new(res[0].clone())
                    }
            }


            impl std::ops::[<$rust_op:camel Assign>] for HpuRadixCiphertext {
                fn [<$rust_op:lower _assign>](&mut self, rhs: Self) {
                    let opcode = $hpu_op.opcode();
                    let proto = &$hpu_op.format().expect("Bind to std::ops a unspecified IOP").proto;

                    HpuCmd::exec_assign(proto, opcode, &[self.0.clone(), rhs.0], &[])
                }
            }

            impl<'a> std::ops::[<$rust_op:camel Assign>]<&'a Self> for HpuRadixCiphertext {
                fn [<$rust_op:lower _assign>](&mut self, rhs: &'a Self) {
                    let opcode = $hpu_op.opcode();
                    let proto = &$hpu_op.format().expect("Bind to std::ops a unspecified IOP").proto;

                    HpuCmd::exec_assign(proto, opcode, &[self.0.clone(), rhs.0.clone()], &[])
                }
            }
        }
    };
}
macro_rules! map_ct_scalar {
    ($hpu_op: ident -> $rust_op: literal) => {
        ::paste::paste! {
            impl std::ops::[<$rust_op:camel>]<u128> for HpuRadixCiphertext {
                type Output = Self;

                fn [<$rust_op:lower>](self, rhs: u128) -> Self::Output {
                    let opcode = $hpu_op.opcode();
                    let proto = &$hpu_op.format().expect("Bind to std::ops a unspecified IOP").proto;

                    let res = HpuCmd::exec(proto, opcode, &[self.0], &[rhs]);
                    Self::Output::new(res[0].clone())
                }
            }

            impl<'a> std::ops::[<$rust_op:camel>]<u128> for &'a HpuRadixCiphertext {
                type Output = HpuRadixCiphertext;

                fn [<$rust_op:lower>](self, rhs: u128) -> Self::Output {
                    let opcode = $hpu_op.opcode();
                    let proto = &$hpu_op.format().expect("Bind to std::ops a unspecified IOP").proto;

                    let res = HpuCmd::exec(proto, opcode, std::slice::from_ref(&self.0), &[rhs]);
                    Self::Output::new(res[0].clone())
                }
            }

            impl std::ops::[<$rust_op:camel Assign>]<u128> for HpuRadixCiphertext {
                fn [<$rust_op:lower _assign>](&mut self, rhs: u128) {
                    let opcode = $hpu_op.opcode();
                    let proto = &$hpu_op.format().expect("Bind to std::ops a unspecified IOP").proto;

                    HpuCmd::exec_assign(proto, opcode, std::slice::from_ref(&self.0), &[rhs])
                }
            }
        }
    };
}

macro_rules! map_scalar_ct {
    ($hpu_op: ident -> $rust_op: literal) => {
        ::paste::paste! {
            impl std::ops::[<$rust_op:camel>]<HpuRadixCiphertext> for u128 {
                type Output = HpuRadixCiphertext;

                fn [<$rust_op:lower>](self, rhs: HpuRadixCiphertext) -> Self::Output {
                    let opcode = $hpu_op.opcode();
                    let proto = &$hpu_op.format().expect("Bind to std::ops a unspecified IOP").proto;

                    let res = HpuCmd::exec(proto, opcode, &[rhs.0], &[self]);
                    Self::Output::new(res[0].clone())
                }
            }
        }
    };
}

map_ct_ct!(IOP_ADD -> "Add");
map_ct_ct!(IOP_SUB -> "Sub");
map_ct_ct!(IOP_MUL  -> "Mul");
// NB: Couldn't be directly mapped since return Div/Rem at once
// map_ct_ct!(IOP_DIV -> "Div");
map_ct_ct!(IOP_MOD -> "Rem");
map_ct_ct!(IOP_SHIFT_L -> "Shl");
map_ct_ct!(IOP_SHIFT_R -> "Shr");
map_ct_ct!(IOP_BW_AND -> "BitAnd");
map_ct_ct!(IOP_BW_OR  -> "BitOr");
map_ct_ct!(IOP_BW_XOR -> "BitXor");

map_ct_scalar!(IOP_ADDS -> "Add");
map_scalar_ct!(IOP_ADDS -> "Add");
map_ct_scalar!(IOP_SUBS -> "Sub");
map_scalar_ct!(IOP_SSUB -> "Sub");
map_ct_scalar!(IOP_MULS -> "Mul");
map_scalar_ct!(IOP_MULS -> "Mul");
