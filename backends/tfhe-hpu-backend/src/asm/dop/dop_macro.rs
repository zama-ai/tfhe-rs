//! DOp definition is repetitive
//!
//! Indeed except the behavior DOp shared a small set of format.
//! And for a given format all the parsing logic is the same
//! A macro rules is used to help with DOp definition

#[macro_export]
macro_rules! impl_dop_parser {
    (
        $asm: literal,
        $opcode: expr,
        $field: ty,
        $fmt: ty
        $(,)?
    ) => {
        ::paste::paste! {
            impl [<DOp $asm:camel>] {
                fn from_args(args: &[arg::Arg]) -> Result<DOp, ParsingError> {
                    let fmt_op = $field::from_args($opcode.into(), args)?;
                    Ok(DOp::[< $asm:upper >](Self(fmt_op)))
                }

                fn from_hex(hex: DOpRepr) -> DOp {
                    DOp::[< $asm:upper >](Self($field::from(&$fmt::from_bits(hex))))
                }

                pub fn opcode() -> u8 {
                    $opcode.into()
                }
            }

            impl ToAsm for [<DOp $asm:camel>]{
                fn name(&self) -> &'static str {
                    $asm
                }
                fn args(&self) -> Vec<arg::Arg> {
                    self.0.args()
                }
                fn dst(&self) -> Vec<arg::Arg> {
                    self.0.dst()
                }
                fn src(&self) -> Vec<arg::Arg> {
                    self.0.src()
                }
            }

            impl ToHex for [<DOp $asm:camel>] {
                fn to_hex(&self) -> DOpRepr {
                    $fmt::from(&self.0).into_bits()
                }
            }
        }
    };
}

#[macro_export]
macro_rules! impl_dop {
    // Arith operations ---------------------------------------------------------------------------
    (
        $asm: literal,
        $opcode: expr,
        PeArithInsn
        $(,)?
    ) => {
        ::paste::paste! {
            #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
            pub struct [<DOp $asm:camel>](pub PeArithInsn);

            impl [<DOp $asm:camel>] {
                pub fn new(dst: RegId, src0: RegId, src1: RegId) -> Self {
                    Self(PeArithInsn {
                        opcode: $opcode,
                        mul_factor: MulFactor(0),
                        src1_rid: src1,
                        src0_rid: src0,
                        dst_rid: dst,
                        })
                }
            }

            impl IsFlush for [<DOp $asm:camel>]{}
            impl_dop_parser!($asm, $opcode, PeArithInsn, PeArithHex);
        }
    };
    // Arith operations with mult_factor ----------------------------------------------------------
    (
        $asm: literal,
        $opcode: expr,
        PeArithInsn_mul_factor
        $(,)?
    ) => {
        ::paste::paste! {
            #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
            pub struct [<DOp $asm:camel>](pub PeArithInsn);

            impl [<DOp $asm:camel>] {
                pub fn new(dst_rid: RegId, src0_rid: RegId, src1_rid: RegId, mul_factor: MulFactor) -> Self {
                    Self(PeArithInsn {
                        opcode: $opcode,
                        mul_factor,
                        src1_rid,
                        src0_rid,
                        dst_rid,
                        })
                }
            }

            impl IsFlush for [<DOp $asm:camel>] {}
            impl_dop_parser!($asm, $opcode, PeArithInsn, PeArithHex);
        }
    };
    // ArithMsg operations ------------------------------------------------------------------------
    (
        $asm: literal,
        $opcode: expr,
        PeArithMsgInsn
        $(,)?
    ) => {
        ::paste::paste! {
            #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
            pub struct [<DOp $asm:camel>](pub PeArithMsgInsn);

            impl [<DOp $asm:camel>] {
                pub fn new(dst_rid: RegId, src_rid: RegId, msg_cst: ImmId) -> Self {
                    Self(PeArithMsgInsn {
                        opcode: $opcode,
                        msg_cst,
                        src_rid,
                        dst_rid,
                        })
                }
                /// Access inner imm for template patching
                pub fn msg_mut(&mut self) -> &mut ImmId {
                    &mut self.0.msg_cst
                }
            }

            impl IsFlush for [<DOp $asm:camel>]{}
            impl_dop_parser!($asm, $opcode, PeArithMsgInsn, PeArithMsgHex);
        }
    };

    // Mem operations ------------------------------------------------------------------------
    // Load flavor
    (
        $asm: literal,
        $opcode: expr,
        PeMemInsn_ld
        $(,)?
    ) => {
        ::paste::paste! {
            #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
            pub struct [<DOp $asm:camel>](pub PeMemInsn);

            impl [<DOp $asm:camel>] {
                pub fn new(rid: RegId, mid: MemId) -> Self {
                    Self(PeMemInsn {
                        opcode: $opcode,
                        slot: mid,
                        rid,
                        })
                }
                /// Access inner rid
                pub fn rid(&self) -> &RegId {
                    &self.0.rid
                }
                /// Access inner memory slot
                pub fn slot(&self) -> &MemId {
                    &self.0.slot
                }
                /// Access inner memory for template patching
                pub fn slot_mut(&mut self) -> &mut MemId {
                    &mut self.0.slot
                }
            }

            impl IsFlush for [<DOp $asm:camel>]{}
            impl_dop_parser!($asm, $opcode, PeMemInsn, PeMemHex);
        }
    };

    // Store flavor
    (
        $asm: literal,
        $opcode: expr,
        PeMemInsn_st
        $(,)?
    ) => {
        ::paste::paste! {
            #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
            pub struct [<DOp $asm:camel>](pub PeMemInsn);

            impl [<DOp $asm:camel>] {
                pub fn new( mid: MemId, rid: RegId) -> Self {
                    Self(PeMemInsn {
                        opcode: $opcode,
                        slot: mid,
                        rid,
                        })
                }
                /// Access inner rid
                pub fn rid(&self) -> &RegId {
                    &self.0.rid
                }
                /// Access inner memory slot
                pub fn slot(&self) -> &MemId {
                    &self.0.slot
                }
                /// Access inner memory for template patching
                pub fn slot_mut(&mut self) -> &mut MemId {
                    &mut self.0.slot
                }
            }

            impl IsFlush for [<DOp $asm:camel>]{}
            impl_dop_parser!($asm, $opcode, PeMemInsn, PeMemHex);
        }
    };

    // Pbs operations ------------------------------------------------------------------------
    (
        $asm: literal,
        $opcode: expr,
        PePbsInsn
        $(,)?
    ) => {
        ::paste::paste! {
            #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
            pub struct [<DOp $asm:camel>](pub PePbsInsn);

            impl [<DOp $asm:camel>] {
                pub fn new(dst_rid: RegId, src_rid: RegId, gid: PbsGid) -> Self {
                    Self(PePbsInsn {
                        opcode: $opcode,
                        gid,
                        src_rid,
                        dst_rid,
                        })
                }
            }

            impl IsFlush for [<DOp $asm:camel>] {
                fn is_flush(&self) -> bool {
                    $opcode.is_flush()
                }
            }
            impl_dop_parser!($asm, $opcode, PePbsInsn, PePbsHex);
        }
    };

    // Sync operations ------------------------------------------------------------------------
    (
        $asm: literal,
        $opcode: expr,
        PeSyncInsn
        $(,)?
    ) => {
        ::paste::paste! {
            #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
            pub struct [<DOp $asm:camel>](pub PeSyncInsn);

            impl [<DOp $asm:camel>] {
                pub fn new(sid: Option<SyncId>) -> Self {
                    Self(PeSyncInsn {
                        opcode: $opcode,
                        sid: sid.unwrap_or(SyncId(0))
                        })
                }

            }

            impl IsFlush for [<DOp $asm:camel>]{}
            impl_dop_parser!($asm, $opcode, PeSyncInsn, PeSyncHex);
        }
    };
}

#[macro_export]
macro_rules! dop {
    (
        $([$asm: literal, $opcode: expr, $type: ty $({$fmt: tt})? $(,$flush: literal)?] $(,)?)*
    ) => {
        ::paste::paste! {
            type AsmCallback = fn(&[arg::Arg]) -> Result<DOp, ParsingError>;
            type HexCallback = fn(DOpRepr) -> DOp;

            $(
                impl_dop!($asm, $opcode, [< $type $(_ $fmt)? >]);
            )*

            /// Aggregate DOp concrete type in one enumeration
            // #[derive(Debug, Clone)]
            #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
            #[enum_dispatch(ToAsm, ToHex, IsFlush)]
            #[allow(non_camel_case_types)]
            pub enum DOp{
                    // $([< $asm:upper >]($type),)*
                    $([< $asm:upper >]([< DOp $asm:camel>]),)*
            }

            impl ToFlush for DOp {
                fn to_flush(&self) -> Self {
                    match self {
                        $(
                            DOp::[< $asm:upper >](inner) => DOp::[< $asm:upper $($flush)?>]
                                ([< DOp $asm:camel $($flush:camel)? >](inner.0.to_flush())),
                        )*
                    }
                }
            }

            impl DOp {
                pub fn from_args(name: &str, args: &[arg::Arg]) -> Result<Self, ParsingError> {
                    if let Some(cb) = DOP_LUT.asm.get(name) {
                        cb(args)
                    } else {
                        Err(ParsingError::Unmatch(format!("{name} unknown")))
                    }
                }
                /// Construct DOp from hex word
                pub fn from_hex(hex: DOpRepr) -> Result<Self, ParsingError> {
                    let raw = DOpRawHex::from_bits(hex);
                    if let Some(cb) = DOP_LUT.hex.get(&raw.opcode()) {
                        Ok(cb(hex))
                    } else {
                        Err(ParsingError::Unmatch(format!("DOp {:x?} unknown  [hex {:x}]", raw.opcode(), hex)))
                    }
                }
            }

            impl std::fmt::Display for DOp {
                fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    write!(f, "{:<width$}", self.name(), width= arg::DOP_MIN_WIDTH)?;
                    for arg in self.args().iter() {
                        write!(f, "{:<width$} ", arg.to_string(), width = arg::ARG_MIN_WIDTH)?
                    }
                    Ok(())
                }
            }

            /// Construct DOp from ASM str
            impl std::str::FromStr for DOp {
                type Err = ParsingError;

                fn from_str(asm: &str) -> Result<Self, Self::Err> {

                    // Split asm string in a vector of arguments
                    let arg_str = asm.split_whitespace().collect::<Vec<_>>();
                    if !arg_str.is_empty() {
                        let name = arg_str[0];
                        let args = arg_str[1..]
                            .iter()
                            .map(|s| {
                                arg::Arg::from_str(s)
                            })
                            .collect::<Result<Vec<_>, _>>()?;

                        Self::from_args(name, args.as_slice())
                    }else {
                        Err(ParsingError::Empty)
                    }
                }
            }

            /// Parser utilities
            /// Hashmap for Name -> to fromArg impl
            struct DOpFromArg{
                asm: HashMap<String, AsmCallback>,
                hex: HashMap<u8, HexCallback>,
            }
            lazy_static! {
                static ref DOP_LUT: DOpFromArg = {

                    let mut dop_from_arg = DOpFromArg{
                        asm: HashMap::new(),
                        hex: HashMap::new(),
                    };

                    $(
                        dop_from_arg.asm.insert(stringify!([< $asm:upper >]).to_string(), [<DOp $asm:camel >]::from_args);
                        dop_from_arg.hex.insert(u8::from($opcode), [<DOp $asm:camel >]::from_hex);
                    )*
                    dop_from_arg
                };
            }
        }
    };
}
