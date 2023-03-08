#[derive(Clone, Copy)]
pub struct SecurityWeights {
    pub(crate) slope: f64,
    pub(crate) bias: f64,
    pub minimal_lwe_dimension: u64,
}

impl SecurityWeights {
    pub fn secure_log2_std(&self, lwe_dimension: u64, ciphertext_modulus_log: f64) -> f64 {
        // ensure to have a minimal on std deviation covering the 2 lowest bits on modular scale
        let epsilon_log2_std_modular = 2.0;
        let epsilon_log2_std = epsilon_log2_std_modular - (ciphertext_modulus_log);
        // ensure the requested lwe_dimension is bigger than the minimal lwe dimension
        if self.minimal_lwe_dimension <= lwe_dimension {
            f64::max(
                self.slope * lwe_dimension as f64 + self.bias,
                epsilon_log2_std,
            )
        } else {
            ciphertext_modulus_log
        }
    }
}
