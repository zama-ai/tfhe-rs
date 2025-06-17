use crate::core_crypto::commons::parameters::CiphertextModulusLog;

pub trait ScalarMul<Scalar> {
    type Output;
    type SideResources;

    fn scalar_mul(&self, rhs: Scalar, side_resources: &mut Self::SideResources) -> Self::Output;
}

pub trait ScalarMulAssign<Scalar> {
    type SideResources;

    fn scalar_mul_assign(&mut self, rhs: Scalar, side_resources: &mut Self::SideResources);
}

pub trait AllocateKeyswtichResult {
    type Output;
    type SideResources;

    fn allocate_keyswitch_result(&self, side_resources: &mut Self::SideResources) -> Self::Output;
}

pub trait Keyswitch<Input, Output> {
    type SideResources;

    fn keyswitch(
        &self,
        input: &Input,
        output: &mut Output,
        side_resources: &mut Self::SideResources,
    );
}

pub trait AllocateClassicPBSModSwitchResult {
    type Output;
    type SideResources;

    fn allocate_classic_mod_switch_result(
        &self,
        side_resources: &mut Self::SideResources,
    ) -> Self::Output;
}

pub trait ClassicPBSModSwitch<Output> {
    type SideResources;

    fn classic_mod_switch(
        &self,
        output_modulus_log: CiphertextModulusLog,
        output: &mut Output,
        side_resources: &mut Self::SideResources,
    );
}

pub trait AllocateDriftTechniqueClassicModSwitchResult {
    type AfterDriftOutput;
    type AfterMsOutput;
    type SideResources;

    fn allocate_drift_technique_classic_mod_switch_result(
        &self,
        side_resources: &mut Self::SideResources,
    ) -> (Self::AfterDriftOutput, Self::AfterMsOutput);
}

pub trait DrifTechniqueClassicModSwitch<Input, OutputAfterDriftTechnique, OutputAfterMs> {
    type SideResources;

    fn drift_technique_and_classic_mod_switch(
        &self,
        output_modulus_log: CiphertextModulusLog,
        input: &Input,
        after_drift_technique: &mut OutputAfterDriftTechnique,
        after_mod_switch: &mut OutputAfterMs,
        side_resources: &mut Self::SideResources,
    );
}

pub trait AllocateBlindRotationResult {
    type Output;
    type SideResources;

    fn allocated_blind_rotation_result(
        &self,
        side_resources: &mut Self::SideResources,
    ) -> Self::Output;
}

pub trait ClassicFftBootstrap<Input, Output, Accumulator> {
    type SideResources;

    fn classic_fft_pbs(
        &self,
        input: &Input,
        output: &mut Output,
        accumulator: &Accumulator,
        side_resources: &mut Self::SideResources,
    );
}
