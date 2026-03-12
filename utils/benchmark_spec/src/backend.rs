use strum::Display;

#[derive(Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum Backend {
    Cpu,
    Cuda,
    Hpu,
}
