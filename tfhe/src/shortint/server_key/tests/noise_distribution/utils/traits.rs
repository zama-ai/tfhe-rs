pub use super::noise_simulation::traits::*;

/// Abstracts several bootstrapping implementation in the same way shortint's ServerKey does
pub trait LweGenericBootstrap<Input, Output, Accumulator> {
    type SideResources;

    fn lwe_generic_bootstrap(
        &self,
        input: &Input,
        output: &mut Output,
        accumulator: &Accumulator,
        side_resources: &mut Self::SideResources,
    );
}

/// Abstracts several blind rotate implementation in the same way shortint's ServerKey does, this
/// one is specific to the PBS 128 blind rotation
pub trait LweGenericBlindRotate128<Input, Output, Accumulator> {
    type SideResources;

    fn lwe_generic_blind_rotate_128(
        &self,
        input: &Input,
        output: &mut Output,
        accumulator: &Accumulator,
        side_resources: &mut Self::SideResources,
    );
}
