use strum::Display;

#[derive(Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum Backend {
    Cpu,
    Cuda,
    Hpu,
}

impl Backend {
    pub fn from_cfg() -> Self {
        if cfg!(feature = "gpu") {
            Backend::Cuda
        } else if cfg!(feature = "hpu") {
            Backend::Hpu
        } else {
            Backend::Cpu
        }
    }
}
