use crate::core_crypto::commons::parameters::CiphertextModulusLog;

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
