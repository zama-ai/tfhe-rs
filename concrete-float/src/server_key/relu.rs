use crate::server_key::Ciphertext;
use crate::ServerKey;

impl ServerKey {
    pub fn relu(&self, ct: &Ciphertext) -> Ciphertext {
        let zero = self.create_trivial_zero_from_ct(ct);
        let ggsw = self.ggsw_ks_cbs(&ct.ct_sign, 0);
        self.cmuxes_full(&ct, &zero, &ggsw)
    }
}
