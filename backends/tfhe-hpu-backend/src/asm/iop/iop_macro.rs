//! IOp mapping
//!
//! IOp currently share one format.
//! Some of them (upper 128) are handled by the fw and are named, the other one is for custom user
//! entries.

#[macro_export]
macro_rules! iop {
    (
        $([ $proto: ident -> $asm: literal, $opcode: expr] $(,)?)*
    ) => {
        ::paste::paste! {
            /// Parser utilities
            /// Hashmap for Name -> to (Opcode, (src, imm, dst))
            pub(crate) struct IOpFromArg {
                pub(crate) asm: HashMap<String, IOpFormat>,
                pub(crate) hex: HashMap<IOpcode, IOpFormat>,
            }
            lazy_static! {
                pub(crate) static ref IOP_LUT: IOpFromArg = {

                    let mut iop_from_arg = IOpFromArg{
                        asm: HashMap::new(),
                        hex: HashMap::new(),
                    };

                    $(
                        let iop_format = IOpFormat{
                            name: stringify!([< $asm:upper >]).to_string(),
                            opcode: IOpcode($opcode),
                            proto: $proto.clone().into()
                        };
                        iop_from_arg.asm.insert(stringify!([< $asm:upper >]).to_string(), iop_format.clone());
                        iop_from_arg.hex.insert(IOpcode($opcode), iop_format);
                    )*
                    iop_from_arg
                };
            }
            // Export each AsmIOpCode as constant
            $(
            lazy_static! {
                pub static ref [< IOP_ $asm:upper >]: AsmIOpcode = {
                        AsmIOpcode{opcode: IOpcode($opcode), format: Some(IOpFormat{
                            name: stringify!([< $asm:upper >]).to_string(),
                            opcode: IOpcode($opcode),
                            proto: $proto.clone().into()
                        })}
                };
            }
            )*

            lazy_static! {
                pub static ref IOP_LIST: Vec<AsmIOpcode> = vec![ $(AsmIOpcode{opcode: IOpcode($opcode), format: Some(IOpFormat{
                            name: stringify!([< $asm:upper >]).to_string(),
                            opcode: IOpcode($opcode),
                            proto: $proto.clone().into()
                        })},)*];
            }
        }
    }
}
