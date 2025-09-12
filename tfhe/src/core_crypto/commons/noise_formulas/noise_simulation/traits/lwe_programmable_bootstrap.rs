pub trait AllocateLweBootstrapResult {
    type Output;
    type SideResources;

    fn allocate_lwe_bootstrap_result(
        &self,
        side_resources: &mut Self::SideResources,
    ) -> Self::Output;
}

pub trait LweClassicFftBootstrap<Input, Output, Accumulator> {
    type SideResources;

    fn lwe_classic_fft_pbs(
        &self,
        input: &Input,
        output: &mut Output,
        accumulator: &Accumulator,
        side_resources: &mut Self::SideResources,
    );
}

pub trait LweClassicFft128Bootstrap<Input, Output, Accumulator> {
    type SideResources;

    fn lwe_classic_fft_128_pbs(
        &self,
        input: &Input,
        output: &mut Output,
        accumulator: &Accumulator,
        side_resources: &mut Self::SideResources,
    );
}
