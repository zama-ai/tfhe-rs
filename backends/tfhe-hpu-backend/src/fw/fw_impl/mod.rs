use super::*;
use crate::asm::{AsmIOpcode, DOp, IOpcode};

pub mod demo;
pub mod ilp;
pub mod ilp_div;
pub mod ilp_log;
pub mod llt;

/// Utility macro to define new FW implementation
#[macro_export]
macro_rules! impl_fw {
    (
        $name: literal
        [
            $($opcode: ident => $func: expr $(;)?)*
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
                fn expand(&self, params: &FwParameters, iopcode: &AsmIOpcode) -> asm::Program<DOp> {
                    let mut prog = program::Program::new(params);
                    match IOpcode::from(iopcode) {
                        $(
                          IOpcode($opcode) => {
                              prog.set_op(iopcode.format.as_ref()
                                  .map(|a| a.name.as_str())
                                  .unwrap_or("default"));
                              $func(&mut prog)
                          },
                        )*
                        _ => panic!("Fw {} doesn't support `{iopcode}`", $name),
                    }
                    prog.into()
                }
            }
        }
    };
}
