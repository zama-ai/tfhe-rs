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
          $func: expr,
          $deg: expr $(,)?
        ]
    ) => {
        ::paste::paste! {
            #[derive(Debug, Clone)]
            pub struct [<Pbs $pbs:camel>](PbsGid);

            impl Default for [< Pbs $pbs:camel >] {
                fn default() -> Self {
                    Self(PbsGid($gid))
                }
            }

            impl PbsLut for [< Pbs $pbs:camel >] {
                fn name(&self) -> &'static str {
                    $pbs
                }
                fn gid(&self) -> PbsGid {
                    self.0
                }
                fn eval(&self, params: &DigitParameters, val: usize) -> usize {
                    $func(params, val)
                }
                fn degree(&self, params: &DigitParameters, deg: usize) -> usize {
                    $deg(params, deg)
                }
            }
        }
    };
}

#[macro_export]
macro_rules! pbs {
    (
        $([$pbs: literal => $gid: literal [
            $func: expr,
            $deg: expr $(,)?
          ]] $(,)?)*
    ) => {
        ::paste::paste! {
            $(
                impl_pbs!($pbs => $gid [ $func, $deg]);
            )*

            /// Aggregate Pbs concrete type in one enumeration
            #[derive(Debug, Clone)]
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
                    pbs_from_arg.hex.insert(pbs.gid(), pbs);
                )*
                pbs_from_arg
            };
}
        }
    };
}
