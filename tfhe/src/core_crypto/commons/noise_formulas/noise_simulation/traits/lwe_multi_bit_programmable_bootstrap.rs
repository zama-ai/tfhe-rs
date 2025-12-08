pub trait AllocateLweMultiBitBlindRotateResult {
    type Output;
    type SideResources;

    fn allocate_lwe_multi_bit_blind_rotate_result(
        &self,
        side_resources: &mut Self::SideResources,
    ) -> Self::Output;
}

pub trait LweMultiBitFftBlindRotate<Input, Output, Accumulator> {
    type SideResources;

    fn lwe_multi_bit_fft_blind_rotate(
        &self,
        input: &Input,
        output: &mut Output,
        accumulator: &Accumulator,
        side_resources: &mut Self::SideResources,
    );
}

pub trait LweMultiBitFft128BlindRotate<Input, Output, Accumulator> {
    type SideResources;

    fn lwe_multi_bit_fft_128_blind_rotate(
        &self,
        input: &Input,
        output: &mut Output,
        accumulator: &Accumulator,
        side_resources: &mut Self::SideResources,
    );
}

pub trait AllocateLweMultiBitBootstrapResult {
    type Output;
    type SideResources;

    fn allocate_lwe_multi_bit_bootstrap_result(
        &self,
        side_resources: &mut Self::SideResources,
    ) -> Self::Output;
}

impl<T: AllocateLweMultiBitBlindRotateResult> AllocateLweMultiBitBootstrapResult for T {
    type Output = <T as AllocateLweMultiBitBlindRotateResult>::Output;
    type SideResources = <T as AllocateLweMultiBitBlindRotateResult>::SideResources;

    fn allocate_lwe_multi_bit_bootstrap_result(
        &self,
        side_resources: &mut Self::SideResources,
    ) -> Self::Output {
        self.allocate_lwe_multi_bit_blind_rotate_result(side_resources)
    }
}

pub trait LweMultiBitFftBootstrap<Input, Output, Accumulator> {
    type SideResources;

    fn lwe_multi_bit_fft_bootstrap(
        &self,
        input: &Input,
        output: &mut Output,
        accumulator: &Accumulator,
        side_resources: &mut Self::SideResources,
    );
}

pub trait LweMultiBitFft128Bootstrap<Input, Output, Accumulator> {
    type SideResources;

    fn lwe_multi_bit_fft_128_bootstrap(
        &self,
        input: &Input,
        output: &mut Output,
        accumulator: &Accumulator,
        side_resources: &mut Self::SideResources,
    );
}
