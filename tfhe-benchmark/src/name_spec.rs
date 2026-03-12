use std::fmt::Display;

pub struct NameSpec<'a> {
    pub bench_prefix: &'a str,
    pub func_name: &'a str,
    pub param_name: &'a str,
    pub is_scalar: bool,
    pub type_name: &'a str,
    pub is_throughput: bool,
}

impl<'a> NameSpec<'a> {
    pub fn new(
        bench_prefix: &'a str,
        func_name: &'a str,
        param_name: &'a str,
        is_scalar: bool,
        type_name: &'a str,
        is_throughput: bool,
    ) -> Self {
        Self {
            bench_prefix,
            func_name,
            param_name,
            is_scalar,
            type_name,
            is_throughput,
        }
    }
}

impl Display for NameSpec<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}::{}", self.bench_prefix, self.func_name)?;
        if self.is_throughput {
            write!(f, "::throughput")?;
        }
        write!(f, "::{}", self.param_name)?;
        if self.is_scalar {
            write!(f, "::scalar")?;
        }
        write!(f, "::{}", self.type_name)
    }
}
