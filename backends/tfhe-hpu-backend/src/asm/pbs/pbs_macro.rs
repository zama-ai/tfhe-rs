//! Macro helper to define PbsLut

#[macro_export]
macro_rules! pbs_lut {
    (
        $pbs: literal => $gid: literal [
          $func: expr,
          $deg: expr,
        ]
    ) => {
        ::paste::paste! {
            #[derive(Debug, Clone, Copy, Serialize, Deserialize)]
            pub struct [<Pbs $pbs:camel>]();

            impl Default for [<Pbs $pbs:camel>]{
                fn default() -> Self {
                    Self ()
                }
            }

            impl PbsLut for [<Pbs $pbs:camel>] {
                fn name(&self) -> &'static str {
                    $pbs
                }
                fn gid(&self) -> usize {
                    $gid
                }
                fn eval(&self, params: &DigitParameters, val: usize) -> usize {
                    $func(params, val)
                }
                fn degree(&self, params: &DigitParameters, deg: usize) -> usize {
                    $deg(params, deg)
                }
            }

            impl PartialEq for [<Pbs $pbs:camel>] {
                fn eq(&self, other: &Self) -> bool {
                    self.gid() == other.gid()
                }
            }
            impl Eq for [<Pbs $pbs:camel>] {}
        }
    };
}
