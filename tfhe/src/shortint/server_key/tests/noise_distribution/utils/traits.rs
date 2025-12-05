pub use super::noise_simulation::traits::*;

pub trait AllocateGenericBootstrapResult {
    type Output;
    type SideResources;

    fn allocate_generic_bootstrap_result(
        &self,
        side_resources: &mut Self::SideResources,
    ) -> Self::Output;
}

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
