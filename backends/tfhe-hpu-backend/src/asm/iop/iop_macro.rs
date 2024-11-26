//! IOp mapping
//!
//! IOp currently share one format.
//! Some of them (upper 128) are handled by the fw and are named, the other one is for custom user
//! entries.

#[macro_export]
macro_rules! iop {
    (
        $([$asm: literal, $opcode: expr, |$src: literal, $imm: literal| -> $dst: literal] $(,)?)*
    ) => {
        ::paste::paste! {
            /// Parser utilities
            /// Hashmap for Name -> to (Opcode, (src, imm, dst))
            struct IOpFromArg {
                asm: HashMap<String, IOpAlias>,
                hex: HashMap<IOpcode, IOpAlias>,
            }
            lazy_static! {
                static ref IOP_LUT: IOpFromArg = {

                    let mut iop_from_arg = IOpFromArg{
                        asm: HashMap::new(),
                        hex: HashMap::new(),
                    };

                    $(
                        let iop_alias = IOpAlias{
                            name: stringify!([< $asm:upper >]).to_string(),
                            opcode: IOpcode($opcode),
                            src: $src,
                            imm: $imm,
                            dst: $dst,
                        };
                        iop_from_arg.asm.insert(stringify!([< $asm:upper >]).to_string(), iop_alias.clone());
                        iop_from_arg.hex.insert(IOpcode($opcode), iop_alias);
                    )*
                    iop_from_arg
                };
            }
            lazy_static! {
                pub static ref IOP_LIST: Vec<AsmIOpcode> = vec![ $(AsmIOpcode{opcode: IOpcode($opcode), alias: Some(IOpAlias{
                            name: stringify!([< $asm:upper >]).to_string(),
                            opcode: IOpcode($opcode),
                            src: $src,
                            imm: $imm,
                            dst: $dst,
                        })},)*];
            }

        }
    }
}
