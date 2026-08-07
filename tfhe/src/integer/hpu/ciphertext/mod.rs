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
    pub fn from_radix_ciphertext(
        cpu_ct: &RadixCiphertext,
        device: &HpuDevice,
        pos: Option<hpu_asm::PhysId>,
    ) -> Self {
        let params = device.params().clone();

        let hpu_ct = cpu_ct
            .blocks
            .iter()
            .map(|blk| HpuLweCiphertextOwned::create_from(blk.ct.as_view(), params.clone()))
            .collect::<Vec<_>>();

        Self(device.new_var_from(hpu_ct, VarMode::Native, pos))
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
    pub fn from_boolean_ciphertext(
        cpu_ct: &BooleanBlock,
        device: &HpuDevice,
        pos: Option<hpu_asm::PhysId>,
    ) -> Self {
        let params = device.params().clone();

        let hpu_ct = vec![HpuLweCiphertextOwned::create_from(
            cpu_ct.0.ct.as_view(),
            params,
        )];
        Self(device.new_var_from(hpu_ct, VarMode::Bool, pos))
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
        dst_pos: Option<hpu_asm::PhysId>,
    ) -> Vec<Self> {
        let rhs_var = rhs_ct.iter().map(|x| x.0.clone()).collect::<Vec<_>>();
        let res_var = HpuCmd::exec(proto, opcode, &rhs_var, rhs_imm, dst_pos);
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

                    let res = HpuCmd::exec(proto, opcode, &[self.0, rhs.0], &[], None);
                    Self::Output::new(res[0].clone())
                }
            }

            impl<'a> std::ops::[<$rust_op:camel>] for &'a HpuRadixCiphertext {
                type Output = HpuRadixCiphertext;

                fn [<$rust_op:lower>](self, rhs: Self) -> Self::Output {
                    let opcode = $hpu_op.opcode();
                    let proto = &$hpu_op.format().expect("Bind to std::ops a unspecified IOP").proto;

                    let res = HpuCmd::exec(proto, opcode, &[self.0.clone(), rhs.0.clone()], &[], None);
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

                    let res = HpuCmd::exec(proto, opcode, &[self.0], &[rhs], None);
                    Self::Output::new(res[0].clone())
                }
            }

            impl<'a> std::ops::[<$rust_op:camel>]<u128> for &'a HpuRadixCiphertext {
                type Output = HpuRadixCiphertext;

                fn [<$rust_op:lower>](self, rhs: u128) -> Self::Output {
                    let opcode = $hpu_op.opcode();
                    let proto = &$hpu_op.format().expect("Bind to std::ops a unspecified IOP").proto;

                    let res = HpuCmd::exec(proto, opcode, std::slice::from_ref(&self.0), &[rhs], None);
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

                    let res = HpuCmd::exec(proto, opcode, &[rhs.0], &[self], None);
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

impl std::ops::Not for HpuRadixCiphertext {
    type Output = Self;

    fn not(self) -> Self::Output {
        let opcode = IOP_BW_NOT.opcode();
        let proto = &IOP_BW_NOT
            .format()
            .expect("Bind to std::ops a unspecified IOP")
            .proto;

        let res = HpuCmd::exec(proto, opcode, &[self.0], &[], None);
        Self::Output::new(res[0].clone())
    }
}

impl std::ops::Not for &HpuRadixCiphertext {
    type Output = HpuRadixCiphertext;

    fn not(self) -> Self::Output {
        let opcode = IOP_BW_NOT.opcode();
        let proto = &IOP_BW_NOT
            .format()
            .expect("Bind to std::ops a unspecified IOP")
            .proto;

        let res = HpuCmd::exec(proto, opcode, std::slice::from_ref(&self.0), &[], None);
        Self::Output::new(res[0].clone())
    }
}

map_ct_scalar!(IOP_ADDS -> "Add");
map_scalar_ct!(IOP_ADDS -> "Add");
map_scalar_ct!(IOP_SSUB -> "Sub");
map_ct_scalar!(IOP_MULS -> "Mul");
map_scalar_ct!(IOP_MULS -> "Mul");

/// Two's complement of `imm` over `width` bits, i.e. `!imm + 1`.
///
/// Lets `ct - imm` be evaluated as `ct + (-imm)` with a plain `ADDS`: the immediate is clear on
/// the host, so the complement costs nothing and the hardware runs the exact same integer
/// addition it would for `ADDS`.
///
/// Masking to `width` is required, not cosmetic: `Immediate::from_cst` derives the number of
/// advertised digits from the *value*, so an unmasked `-1` would claim 64 digits and push a
/// needlessly long IOp stream for, say, an 8-bit operand.
fn neg_imm(width: usize, imm: HpuImm) -> HpuImm {
    let mask = if width >= HpuImm::BITS as usize {
        HpuImm::MAX
    } else {
        (1 << width) - 1
    };
    imm.wrapping_neg() & mask
}

/// `ct - imm`, lowered to `ADDS` with a negated immediate (see [`neg_imm`]).
///
/// Mirrors what `map_ct_scalar!(IOP_SUBS -> "Sub")` used to generate, but targets `IOP_ADDS`.
/// `IOP_SUBS` itself is untouched and still available for direct IOp submission.
impl std::ops::Sub<HpuImm> for HpuRadixCiphertext {
    type Output = Self;

    fn sub(self, rhs: HpuImm) -> Self::Output {
        &self - rhs
    }
}

impl std::ops::Sub<HpuImm> for &HpuRadixCiphertext {
    type Output = HpuRadixCiphertext;

    fn sub(self, rhs: HpuImm) -> Self::Output {
        let opcode = IOP_ADDS.opcode();
        let proto = &IOP_ADDS
            .format()
            .expect("Bind to std::ops a unspecified IOP")
            .proto;

        let rhs = neg_imm(self.0.int_width(), rhs);
        let res = HpuCmd::exec(proto, opcode, std::slice::from_ref(&self.0), &[rhs], None);
        HpuRadixCiphertext::new(res[0].clone())
    }
}

impl std::ops::SubAssign<HpuImm> for HpuRadixCiphertext {
    fn sub_assign(&mut self, rhs: HpuImm) {
        let opcode = IOP_ADDS.opcode();
        let proto = &IOP_ADDS
            .format()
            .expect("Bind to std::ops a unspecified IOP")
            .proto;

        let rhs = neg_imm(self.0.int_width(), rhs);
        HpuCmd::exec_assign(proto, opcode, std::slice::from_ref(&self.0), &[rhs])
    }
}

/// Whether vacated positions are zero-filled rather than wrapped around.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ShiftRotKind {
    ShiftRight,
    ShiftLeft,
    RotateRight,
    RotateLeft,
}

impl ShiftRotKind {
    fn is_shift(self) -> bool {
        matches!(self, Self::ShiftRight | Self::ShiftLeft)
    }

    /// The IOp evaluating this operation with a clear amount.
    fn iop(self) -> &'static hpu_asm::AsmIOpcode {
        match self {
            Self::ShiftRight => &IOP_SHIFTS_R,
            Self::ShiftLeft => &IOP_SHIFTS_L,
            Self::RotateRight => &IOP_ROTS_R,
            Self::RotateLeft => &IOP_ROTS_L,
        }
    }
}

/// Encodes a clear shift/rotate amount into the control word the scalar shift/rotate IOps expect.
///
/// Those IOps select with plaintext multiplications, which need one *digit* per control bit, and
/// the IOp language cannot slice a digit out of a packed immediate — so the amount is advertised
/// bit per bit, which costs the host nothing since it holds it in the clear:
///
/// ```text
///  digit i        = bit i of (amount % width)   for i < log2(width)
///  digit log2(w)  = keep = 1 if amount < width, else 0
/// ```
///
/// `keep` is what makes an overflowing *shift* return zero at no hardware cost; rotations ignore it
/// and always set it, `amount % width` being the whole story for them.
///
/// This mirrors `shiftrot_ctrl_word` of the compiler that emits these IOps — one digit per control
/// bit, *not* the `amount[stg / msg_w]` packing that the encrypted-amount datapath reads.
///
/// # Panics
///
/// Panics if `width` is not a power of two, which the control word cannot express.
fn shiftrot_ctrl_imm(width: usize, msg_w: usize, kind: ShiftRotKind, imm: HpuImm) -> HpuImm {
    assert!(
        width.is_power_of_two(),
        "Scalar shift/rotate needs a power of two width, got {width}"
    );
    let log_w = width.ilog2();
    let mut ctrl = 0 as HpuImm;
    // Only the low log2(width) bits matter, which is exactly `imm % width`.
    for i in 0..log_w {
        ctrl |= ((imm >> i) & 1) << (i as usize * msg_w);
    }
    if !kind.is_shift() || imm < width as HpuImm {
        ctrl |= 1 << (log_w as usize * msg_w);
    }
    ctrl
}

/// Submits a scalar shift/rotate, encoding `imm` on the way (see [`shiftrot_ctrl_imm`]).
fn shiftrot_scalar(ct: &HpuVarWrapped, kind: ShiftRotKind, imm: HpuImm) -> HpuVarWrapped {
    let iop = kind.iop();
    let proto = &iop
        .format()
        .expect("Bind to std::ops a unspecified IOP")
        .proto;
    let ctrl = shiftrot_ctrl_imm(ct.int_width(), msg_width(ct), kind, imm);
    let res = HpuCmd::exec(proto, iop.opcode(), std::slice::from_ref(ct), &[ctrl], None);
    res[0].clone()
}

/// In-place flavor of [`shiftrot_scalar`].
fn shiftrot_scalar_assign(ct: &HpuVarWrapped, kind: ShiftRotKind, imm: HpuImm) {
    let iop = kind.iop();
    let proto = &iop
        .format()
        .expect("Bind to std::ops a unspecified IOP")
        .proto;
    let ctrl = shiftrot_ctrl_imm(ct.int_width(), msg_width(ct), kind, imm);
    HpuCmd::exec_assign(proto, iop.opcode(), std::slice::from_ref(ct), &[ctrl])
}

/// Message width of a block, which the ciphertext only exposes indirectly.
fn msg_width(ct: &HpuVarWrapped) -> usize {
    ct.int_width() / ct.blk_width()
}

/// `ct >> imm` and `ct << imm`, with a clear amount: shifting by the operand width or more yields
/// zero, as the `keep` digit of the control word nulls every block.
impl std::ops::Shr<HpuImm> for HpuRadixCiphertext {
    type Output = Self;

    fn shr(self, rhs: HpuImm) -> Self::Output {
        &self >> rhs
    }
}

impl std::ops::Shr<HpuImm> for &HpuRadixCiphertext {
    type Output = HpuRadixCiphertext;

    fn shr(self, rhs: HpuImm) -> Self::Output {
        HpuRadixCiphertext::new(shiftrot_scalar(&self.0, ShiftRotKind::ShiftRight, rhs))
    }
}

impl std::ops::ShrAssign<HpuImm> for HpuRadixCiphertext {
    fn shr_assign(&mut self, rhs: HpuImm) {
        shiftrot_scalar_assign(&self.0, ShiftRotKind::ShiftRight, rhs)
    }
}

impl std::ops::Shl<HpuImm> for HpuRadixCiphertext {
    type Output = Self;

    fn shl(self, rhs: HpuImm) -> Self::Output {
        &self << rhs
    }
}

impl std::ops::Shl<HpuImm> for &HpuRadixCiphertext {
    type Output = HpuRadixCiphertext;

    fn shl(self, rhs: HpuImm) -> Self::Output {
        HpuRadixCiphertext::new(shiftrot_scalar(&self.0, ShiftRotKind::ShiftLeft, rhs))
    }
}

impl std::ops::ShlAssign<HpuImm> for HpuRadixCiphertext {
    fn shl_assign(&mut self, rhs: HpuImm) {
        shiftrot_scalar_assign(&self.0, ShiftRotKind::ShiftLeft, rhs)
    }
}

/// Rotations by a clear amount. There is no `std::ops` trait for those, hence named methods; the
/// amount is taken modulo the operand width, so no amount is out of range.
impl HpuRadixCiphertext {
    pub fn rotate_right(&self, amount: HpuImm) -> Self {
        Self::new(shiftrot_scalar(&self.0, ShiftRotKind::RotateRight, amount))
    }

    pub fn rotate_right_assign(&mut self, amount: HpuImm) {
        shiftrot_scalar_assign(&self.0, ShiftRotKind::RotateRight, amount)
    }

    pub fn rotate_left(&self, amount: HpuImm) -> Self {
        Self::new(shiftrot_scalar(&self.0, ShiftRotKind::RotateLeft, amount))
    }

    pub fn rotate_left_assign(&mut self, amount: HpuImm) {
        shiftrot_scalar_assign(&self.0, ShiftRotKind::RotateLeft, amount)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// The control word is a cross-repository contract: these are the very values the compiler
    /// emitting the scalar shift/rotate IOps asserts on its side, so any drift breaks here first.
    #[test]
    fn test_shiftrot_ctrl_imm() {
        let (width, msg_w) = (64, 2);
        let shl = |imm| shiftrot_ctrl_imm(width, msg_w, ShiftRotKind::ShiftLeft, imm);
        let rol = |imm| shiftrot_ctrl_imm(width, msg_w, ShiftRotKind::RotateLeft, imm);

        // 7 == 0b000111 -> digits [1, 1, 1, 0, 0, 0 | keep = 1]
        assert_eq!(shl(7), 0x1015);
        // 70 >= 64 -> keep = 0, the result is null whatever the digits say
        assert_eq!(shl(70), 0x0014);
        // A rotation has no overshift: 70 rotates like 70 % 64 == 6, keep stays set.
        assert_eq!(rol(70), 0x1014);
        assert_eq!(rol(6), shl(6));

        assert_eq!(shl(0), 0x1000, "keep alone");
        assert_eq!(shl(63), 0x1555, "every amount bit set");
        assert_eq!(shl(64), 0x0000, "shifting everything out");

        // The digit layout must not depend on the block width beyond the digit stride.
        assert_eq!(shiftrot_ctrl_imm(8, 2, ShiftRotKind::ShiftLeft, 3), 0x45);
        assert_eq!(shiftrot_ctrl_imm(8, 4, ShiftRotKind::ShiftLeft, 3), 0x1011);
    }
}
