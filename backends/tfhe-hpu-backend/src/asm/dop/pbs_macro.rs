//! Pbs definition is repetitive
//!
//! A macro rules is used to help with Pbs definition

pub const CMP_INFERIOR: usize = 0;
pub const CMP_EQUAL: usize = 1;
pub const CMP_SUPERIOR: usize = 2;

#[macro_export]
macro_rules! impl_pbs {
    (
        $pbs: literal => $gid: literal [
            $(@$id:literal => {
                $func: expr;
                $deg: expr$(;)?
                }$(,)?)+
        ]
    ) => {
        ::paste::paste! {
            #[derive(Debug, PartialEq, Eq, Clone)]
            pub struct [<Pbs $pbs:camel>]();

            impl Default for [<Pbs $pbs:camel>]{
                fn default() -> Self {
                    Self ()
                }
            }

            impl PbsLut for [< Pbs $pbs:camel >] {
                fn name(&self) -> &'static str {
                    $pbs
                }
                fn gid(&self) -> PbsGid {
                    PbsGid($gid)
                }
                fn lut_nb(&self) -> u8 {
                    if let Some(max) = [$($id,)*].iter().max() {
                        max +1} else {0}
                }
                fn lut_lg(&self) -> u8 {
                    ceil_ilog2(&self.lut_nb())
                }

                fn fn_at(&self, pos: usize, params: &DigitParameters, val: usize ) -> usize {
                    match pos {
                        $(
                            $id => ($func)(params, val),
                        )*
                        _ => {
                            // Unspecified -> Default to identity
                            val
                        },
                    }
                }

                fn deg_at(&self, pos: usize, params: &DigitParameters, deg: usize ) -> usize {
                    match pos {
                        $(
                            $id => ($deg)(params, deg),
                        )*
                        _ => {
                            // Unspecified -> Default to identity
                            deg
                        },
                    }
                }
            }
        }
    };
}

#[macro_export]
macro_rules! pbs {
    (
        $([$pbs: literal => $gid: literal [
            $(@$id:literal => {
                $func: expr;
                $deg: expr$(;)?
                }$(,)?)+]
          ] $(,)?)*
    ) => {
        ::paste::paste! {
            $(
            impl_pbs!($pbs => $gid [ $(@$id => {$func; $deg;},)*]);
            )*

            /// Aggregate Pbs concrete type in one enumeration
            #[derive(Debug, Clone, PartialEq, Eq)]
            #[enum_dispatch(PbsLut)]
            pub enum Pbs{
                    $([< $pbs:camel >]([< Pbs $pbs:camel >]),)*
                }

            impl std::fmt::Display for Pbs {
                fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    write!(f, "Pbs{}", self.name())
                }
            }

            impl std::str::FromStr for Pbs {
                type Err = ParsingError;

                fn from_str(name: &str) -> Result<Self, Self::Err> {
                    if let Some(lut) = PBS_LUT.asm.get(name) {
                        Ok(lut.clone())
                    } else {
                        Err(ParsingError::Unmatch(format!("Pbs{name} unknown")))
                    }

                }
            }

            impl Pbs {
                pub fn from_hex(gid: PbsGid) -> Result<Self, ParsingError> {
                    if let Some(pbs) = PBS_LUT.hex.get(&gid) {
                        Ok(pbs.clone())
                    } else {
                        Err(ParsingError::Unmatch(format!("Pbs {gid:?} unknown")))
                    }
                }

                pub fn list_all() -> Vec<Self> {
                    PBS_LUT.hex.values().map(|pbs| pbs.clone()).collect::<Vec<_>>()
                }
            }

            /// Parser utilities
            /// Hashmap for Name -> to fromArg impl
            struct PbsFromArg{
                asm: HashMap<String, Pbs>,
                hex: HashMap<PbsGid, Pbs>,
            }

            lazy_static! {
            static ref PBS_LUT: PbsFromArg = {

                let mut pbs_from_arg = PbsFromArg{
                    asm: HashMap::new(),
                    hex: HashMap::new(),
                };

                $(
                    let pbs = Pbs::[< $pbs:camel >]([< Pbs $pbs >]::default());
                    pbs_from_arg.asm.insert(stringify!([< $pbs:camel >]).to_string(), pbs.clone());
                    let evicted = pbs_from_arg.hex.insert(pbs.gid(), pbs.clone());
                    assert!(evicted.is_none(), "Error with {}: gid {} is already use by {:?}",
stringify!([< $pbs:camel >]), pbs.gid(), evicted.unwrap());

                )*
                pbs_from_arg
            };
}
        }
    };
}
