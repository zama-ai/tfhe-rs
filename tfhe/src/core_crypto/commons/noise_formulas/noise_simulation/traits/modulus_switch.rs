use crate::core_crypto::commons::parameters::{CiphertextModulusLog, LweBskGroupingFactor};

pub trait AllocateStandardModSwitchResult {
    type Output;
    type SideResources;

    fn allocate_standard_mod_switch_result(
        &self,
        side_resources: &mut Self::SideResources,
    ) -> Self::Output;
}

pub trait StandardModSwitch<Output> {
    type SideResources;

    fn standard_mod_switch(
        &self,
        output_modulus_log: CiphertextModulusLog,
        output: &mut Output,
        side_resources: &mut Self::SideResources,
    );
}

pub trait AllocateDriftTechniqueStandardModSwitchResult {
    type AfterDriftOutput;
    type AfterMsOutput;
    type SideResources;

    fn allocate_drift_technique_standard_mod_switch_result(
        &self,
        side_resources: &mut Self::SideResources,
    ) -> (Self::AfterDriftOutput, Self::AfterMsOutput);
}

pub trait DriftTechniqueStandardModSwitch<Input, OutputAfterDriftTechnique, OutputAfterMs> {
    type SideResources;

    fn drift_technique_and_standard_mod_switch(
        &self,
        output_modulus_log: CiphertextModulusLog,
        input: &Input,
        after_drift_technique: &mut OutputAfterDriftTechnique,
        after_mod_switch: &mut OutputAfterMs,
        side_resources: &mut Self::SideResources,
    );
}

pub trait AllocateMultiBitModSwitchResult {
    type Output;
    type SideResources;

    fn allocate_multi_bit_mod_switch_result(
        &self,
        side_resources: &mut Self::SideResources,
    ) -> Self::Output;
}

pub trait MultiBitModSwitch<Output> {
    type SideResources;

    fn multi_bit_mod_switch(
        &self,
        grouping_factor: LweBskGroupingFactor,
        output_modulus_log: CiphertextModulusLog,
        output: &mut Output,
        side_resources: &mut Self::SideResources,
    );
}

pub trait AllocateCenteredBinaryShiftedStandardModSwitchResult {
    type Output;
    type SideResources;

    fn allocate_centered_binary_shifted_standard_mod_switch_result(
        &self,
        side_resources: &mut Self::SideResources,
    ) -> Self::Output;
}

pub trait CenteredBinaryShiftedStandardModSwitch<Output> {
    type SideResources;

    fn centered_binary_shifted_and_standard_mod_switch(
        &self,
        output_modulus_log: CiphertextModulusLog,
        output: &mut Output,
        side_resources: &mut Self::SideResources,
    );
}
