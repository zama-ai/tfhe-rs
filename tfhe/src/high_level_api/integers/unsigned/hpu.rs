//! Define explicit HPU FheUint type
//! Purpose of this type is to use HPU computation power while keeping
//! a global CPU key register in the HighLevelApi
//!
//! By this way, user can easily and explicitly mixed computation between
//! Cpu and Hpu.

use super::*;
use crate::high_level_api::traits::HwXfer;
use crate::integer::hpu::ciphertext::HpuRadixCiphertext;
use crate::Tag;
use tfhe_hpu_backend::prelude::*;

/// An explicit Hpu FHE unsigned integer
///
/// This struct is generic over some Id, as its the Id
/// that controls how many bit they represent.
///
/// Its the type that overloads the operators (`+`, `-`, `*`),
/// since the `FheUint` type is not `Copy` the operators are also overloaded
/// to work with references.
//
#[derive(Clone)]
pub struct HpuFheUint<Id: FheUintId> {
    ciphertext: HpuRadixCiphertext,
    pub(in crate::high_level_api::integers) id: Id,
    pub(crate) tag: Tag,
}

impl<Id: FheUintId> HwXfer<HpuDevice> for FheUint<Id> {
    type Output = HpuFheUint<Id>;

    fn clone_on(&self, device: &HpuDevice) -> Self::Output {
        let hpu_ct = match &self.ciphertext {
            inner::RadixCiphertext::Cpu(cpu_ct) => {
                HpuRadixCiphertext::from_radix_ciphertext(cpu_ct, device)
            }
            //NB: this entry is only used when other tfhe-backends are enabled
            #[allow(unreachable_patterns)]
            _ => panic!("Only native movement are supported"),
        };
        Self::Output {
            ciphertext: hpu_ct,
            id: self.id,
            tag: self.tag.clone(),
        }
    }

    fn mv_on(self, device: &HpuDevice) -> Self::Output {
        // Xfer with Hpu is always copy.
        // Thus rely on copy implementation but from rust PoV FheUint is consumed
        Self::clone_on(&self, device)
    }
}

impl<Id: FheUintId> From<HpuFheUint<Id>> for FheUint<Id> {
    fn from(value: HpuFheUint<Id>) -> Self {
        let HpuFheUint {
            ciphertext,
            id,
            tag,
        } = value;
        let cpu_ct = ciphertext.to_radix_ciphertext();
        Self {
            ciphertext: inner::RadixCiphertext::Cpu(cpu_ct),
            id,
            tag,
        }
    }
}

/// Macro to export std::ops rust trait from HpuVar on HpuFheUint
#[macro_export]
/// Easily map an Hpu operation to std::ops rust trait
macro_rules! export_std_ops {
    ($rust_op: literal) => {
        ::paste::paste! {
            #[allow(unused)]
            use std::ops::[<$rust_op:camel>];
            impl<Id: FheUintId> std::ops::[<$rust_op:camel>] for HpuFheUint<Id> {
                type Output = HpuFheUint<Id>;

                fn [<$rust_op:lower>](self, rhs: Self) -> Self::Output {
                    let Self{
                        ciphertext,
                        id,
                        tag } = self;
                    let inner_dst_var = ciphertext.0.[<$rust_op:lower>](rhs.ciphertext.0);

                    Self{ciphertext: HpuRadixCiphertext(inner_dst_var), id, tag}
                }
            }

            #[allow(unused)]
            use std::ops::[<$rust_op:camel Assign>];
            impl<Id: FheUintId> std::ops::[<$rust_op:camel Assign>] for HpuFheUint<Id> {
                fn [<$rust_op:lower _assign>](&mut self, rhs: Self) {
                    self.ciphertext.0.[<$rust_op:lower _assign>](rhs.ciphertext.0);
                }
            }
        }
    };
}

// Export ct_ct std::ops
export_std_ops!("Add");
export_std_ops!("Sub");
export_std_ops!("Mul");
export_std_ops!("BitAnd");
export_std_ops!("BitOr");
export_std_ops!("BitXor");
// TODO expose other std::ops

// For bench purpose also expose iop_ct/iop_imm function
impl<Id: FheUintId> HpuFheUint<Id> {
    pub fn iop_ct(self, name: hpu_asm::IOpName, rhs: Self) -> Self {
        let Self {
            ciphertext,
            id,
            tag,
        } = self;
        let inner_dst_var = ciphertext.0.iop_ct(name, rhs.ciphertext.0);
        Self {
            ciphertext: HpuRadixCiphertext(inner_dst_var),
            id,
            tag,
        }
    }

    pub fn iop_ct_assign(&mut self, name: hpu_asm::IOpName, rhs: Self) {
        self.ciphertext.0.iop_ct_assign(name, rhs.ciphertext.0)
    }

    pub fn iop_imm(self, name: hpu_asm::IOpName, rhs: usize) -> Self {
        let Self {
            ciphertext,
            id,
            tag,
        } = self;
        let inner_dst_var = ciphertext.0.iop_imm(name, rhs);
        Self {
            ciphertext: HpuRadixCiphertext(inner_dst_var),
            id,
            tag,
        }
    }

    pub fn iop_imm_assign(&mut self, name: hpu_asm::IOpName, rhs: usize) {
        self.ciphertext.0.iop_imm_assign(name, rhs)
    }
}
