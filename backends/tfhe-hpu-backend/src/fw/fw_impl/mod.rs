use super::*;
use crate::asm::iop::IOp;
use crate::asm::{ArchProperties, Asm};
use program::Program;

pub mod ilp;

/// Utility macro to define new FW implementation
#[macro_export]
macro_rules! impl_fw {
    (
        $name: literal
        [
            $($op: literal => $func: expr $(;)?)*
        ]
    ) => {
        ::paste::paste! {
            pub struct [<$name:camel>]();

            impl Default for [<$name:camel>]{
                fn default() -> Self {
                    Self()
                }
            }

            impl Fw for [<$name:camel>]{
            fn expand(&mut self, arch: &ArchProperties, ops: &[IOp]) -> Program {
                let mut prog = Program::new(arch);

                for op in ops.iter() {
                    match op.name() {
                        $(
                          $op => $func(&mut prog, op),
                        )*
                        _ => panic!("Fw {} doesn't support {op:?}", $name),
                     }

                }
                prog
            }
        }
        }
    };
}
