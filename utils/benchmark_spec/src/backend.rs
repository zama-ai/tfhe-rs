use strum::Display;

#[derive(Debug, Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum Backend {
    Cpu,
    Cuda,
    Hpu,
}

pub fn bench_backend_from_cfg() -> Backend {
    if cfg!(feature = "gpu") {
        Backend::Cuda
    } else if cfg!(feature = "hpu") {
        Backend::Hpu
    } else {
        Backend::Cpu
    }
}
