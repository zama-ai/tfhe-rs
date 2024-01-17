use crate::integer::ciphertext::RadixCiphertext;
use crate::integer::wopbs::WopbsKey;

pub(in crate::high_level_api) fn wopbs_radix(
    wopbs_key: &WopbsKey,
    server_key: &crate::integer::ServerKey,
    ct_in: &RadixCiphertext,
    func: impl Fn(u64) -> u64,
) -> RadixCiphertext
where
    RadixCiphertext: crate::integer::IntegerCiphertext,
{
    let switched_ct = wopbs_key.keyswitch_to_wopbs_params(server_key, ct_in);
    let luts = wopbs_key.generate_lut_radix(&switched_ct, func);
    let res = wopbs_key.wopbs(&switched_ct, &luts);
    wopbs_key.keyswitch_to_pbs_params(&res)
}

pub(in crate::high_level_api) fn bivariate_wopbs_radix(
    wopbs_key: &WopbsKey,
    server_key: &crate::integer::ServerKey,
    lhs: &RadixCiphertext,
    rhs: &RadixCiphertext,
    func: impl Fn(u64, u64) -> u64,
) -> RadixCiphertext
where
    RadixCiphertext: crate::integer::IntegerCiphertext,
{
    let switched_lhs = wopbs_key.keyswitch_to_wopbs_params(server_key, lhs);
    let switched_rhs = wopbs_key.keyswitch_to_wopbs_params(server_key, rhs);
    let lut = wopbs_key.generate_lut_bivariate_radix(&switched_lhs, &switched_rhs, func);
    let res = wopbs_key.bivariate_wopbs_with_degree(&switched_lhs, &switched_rhs, &lut);
    wopbs_key.keyswitch_to_pbs_params(&res)
}

pub trait WopbsEvaluationKey<ServerKey, Ciphertext> {
    fn apply_wopbs(&self, sks: &ServerKey, ct: &Ciphertext, f: impl Fn(u64) -> u64) -> Ciphertext;

    fn apply_bivariate_wopbs(
        &self,
        sks: &ServerKey,
        lhs: &Ciphertext,
        rhs: &Ciphertext,
        f: impl Fn(u64, u64) -> u64,
    ) -> Ciphertext;
}

impl WopbsEvaluationKey<crate::integer::ServerKey, RadixCiphertext> for WopbsKey {
    fn apply_wopbs(
        &self,
        sks: &crate::integer::ServerKey,
        ct: &RadixCiphertext,
        f: impl Fn(u64) -> u64,
    ) -> RadixCiphertext {
        let mut tmp_ct: RadixCiphertext;

        let ct = if ct.block_carries_are_empty() {
            ct
        } else {
            tmp_ct = ct.clone();
            sks.full_propagate_parallelized(&mut tmp_ct);
            &tmp_ct
        };

        wopbs_radix(self, sks, ct, f)
    }

    fn apply_bivariate_wopbs(
        &self,
        sks: &crate::integer::ServerKey,
        lhs: &RadixCiphertext,
        rhs: &RadixCiphertext,
        f: impl Fn(u64, u64) -> u64,
    ) -> RadixCiphertext {
        let mut tmp_lhs: RadixCiphertext;
        let mut tmp_rhs: RadixCiphertext;

        // Clean carries to have a small wopbs to compute
        let (lhs, rhs) = match (lhs.block_carries_are_empty(), rhs.block_carries_are_empty()) {
            (true, true) => (lhs, rhs),
            (true, false) => {
                tmp_rhs = rhs.clone();
                sks.full_propagate_parallelized(&mut tmp_rhs);
                (lhs, &tmp_rhs)
            }
            (false, true) => {
                tmp_lhs = lhs.clone();
                sks.full_propagate_parallelized(&mut tmp_lhs);
                (&tmp_lhs, rhs)
            }
            (false, false) => {
                tmp_lhs = lhs.clone();
                tmp_rhs = rhs.clone();
                rayon::join(
                    || sks.full_propagate_parallelized(&mut tmp_lhs),
                    || sks.full_propagate_parallelized(&mut tmp_rhs),
                );
                (&tmp_lhs, &tmp_rhs)
            }
        };

        bivariate_wopbs_radix(self, sks, lhs, rhs, f)
    }
}
