#![warn(clippy::nursery)]
#![warn(clippy::pedantic)]
#![warn(clippy::style)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::cast_precision_loss)] // u64 to f64
#![allow(clippy::cast_possible_truncation)] // u64 to usize
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::suboptimal_flops)]
#![allow(clippy::cast_possible_wrap)]
#![warn(unused_results)]

pub mod gaussian_noise;

pub(crate) mod utils {
    pub fn square<V>(v: V) -> V
    where
        V: std::ops::Mul<Output = V> + Copy,
    {
        v * v
    }
}
