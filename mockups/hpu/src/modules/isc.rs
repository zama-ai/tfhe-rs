use tfhe::tfhe_hpu_backend::prelude::*;

use crate::mockup_params::IscSimParameters;

pub struct InstructionScheduler {}

impl InstructionScheduler {
    pub fn new(params: IscSimParameters) -> Self {
        Self {}
    }

    pub fn schedule(&mut self, dops: Vec<hpu_asm::DOp>) -> Vec<hpu_asm::DOp> {
        dops
    }
}
