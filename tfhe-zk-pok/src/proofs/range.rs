use super::*;

#[derive(Clone, Debug)]
pub struct PublicParams<G: Curve> {
    g_lists: GroupElements<G>,
    hash: [u8; LEGACY_HASH_DS_LEN_BYTES],
    hash_s: [u8; LEGACY_HASH_DS_LEN_BYTES],
    hash_t: [u8; LEGACY_HASH_DS_LEN_BYTES],
    hash_agg: [u8; LEGACY_HASH_DS_LEN_BYTES],
}

impl<G: Curve> PublicParams<G> {
    pub fn from_vec(
        g_list: Vec<Affine<G::Zp, G::G1>>,
        g_hat_list: Vec<Affine<G::Zp, G::G2>>,
        hash: [u8; LEGACY_HASH_DS_LEN_BYTES],
        hash_s: [u8; LEGACY_HASH_DS_LEN_BYTES],
        hash_t: [u8; LEGACY_HASH_DS_LEN_BYTES],
        hash_agg: [u8; LEGACY_HASH_DS_LEN_BYTES],
    ) -> Self {
        Self {
            g_lists: GroupElements::from_vec(g_list, g_hat_list),
            hash,
            hash_s,
            hash_t,
            hash_agg,
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct PrivateParams<G: Curve> {
    alpha: G::Zp,
}

#[derive(Clone, Debug)]
pub struct PublicCommit<G: Curve> {
    l: usize,
    v_hat: G::G2,
}

#[derive(Clone, Debug)]
pub struct PrivateCommit<G: Curve> {
    x: u64,
    r: G::Zp,
}

#[derive(Clone, Debug)]
pub struct Proof<G: Curve> {
    c_y: G::G1,
    c_hat: G::G2,
    pi: G::G1,
}

pub fn crs_gen<G: Curve>(max_nbits: usize, rng: &mut impl RngExt) -> PublicParams<G> {
    let alpha = G::Zp::rand(rng);
    PublicParams {
        g_lists: GroupElements::new(max_nbits, alpha),
        hash: core::array::from_fn(|_| rng.random()),
        hash_s: core::array::from_fn(|_| rng.random()),
        hash_t: core::array::from_fn(|_| rng.random()),
        hash_agg: core::array::from_fn(|_| rng.random()),
    }
}

pub fn commit<G: Curve>(
    x: u64,
    l: usize,
    public: &PublicParams<G>,
    rng: &mut impl RngExt,
) -> (PublicCommit<G>, PrivateCommit<G>) {
    let g_hat = G::G2::GENERATOR;

    let r = G::Zp::rand(rng);
    let v_hat = g_hat.mul_scalar(r)
        + G::G2::projective(public.g_lists.g_hat_list[1]).mul_scalar(G::Zp::from_u64(x));

    (PublicCommit { l, v_hat }, PrivateCommit { x, r })
}

pub fn prove<G: Curve>(
    public: (&PublicParams<G>, &PublicCommit<G>),
    private_commit: &PrivateCommit<G>,
    rng: &mut impl RngExt,
) -> Proof<G> {
    let &PrivateCommit { x, r } = private_commit;
    let &PublicCommit { l, v_hat } = public.1;
    let PublicParams {
        g_lists,
        hash,
        hash_s,
        hash_t,
        hash_agg,
    } = public.0;
    let n = g_lists.message_len;

    let g_list = &g_lists.g_list;
    let g_hat_list = &g_lists.g_hat_list;

    let g = G::G1::GENERATOR;
    let g_hat = G::G2::GENERATOR;
    let gamma = G::Zp::rand(rng);
    let gamma_y = G::Zp::rand(rng);

    let mut x_bits = vec![0u64; n];
    for (i, x_bits) in x_bits[0..l].iter_mut().enumerate() {
        *x_bits = (x >> i) & 1;
    }
    let x_bits = OneBased(x_bits);

    let c_hat = {
        let mut c = g_hat.mul_scalar(gamma);
        for j in 1..l + 1 {
            let term = if x_bits[j] != 0 {
                G::G2::projective(g_hat_list[j])
            } else {
                G::G2::ZERO
            };
            c += term;
        }
        c
    };

    let mut proof_x = -G::G1::projective(g_list[n]).mul_scalar(r);
    for i in 1..l + 1 {
        let mut term = G::G1::projective(g_list[n + 1 - i]).mul_scalar(gamma);
        for j in 1..l + 1 {
            if j != i {
                let term_inner = if x_bits[j] != 0 {
                    G::G1::projective(g_list[n + 1 - i + j])
                } else {
                    G::G1::ZERO
                };
                term += term_inner;
            }
        }

        for _ in 1..i {
            term = term.double();
        }
        proof_x += term;
    }

    let mut y = vec![G::Zp::ZERO; n];
    G::Zp::hash(
        &mut y,
        &[
            hash,
            v_hat.to_le_bytes().as_ref(),
            c_hat.to_le_bytes().as_ref(),
        ],
    );
    let y = OneBased(y);
    let mut c_y = g.mul_scalar(gamma_y);
    for j in 1..l + 1 {
        c_y += G::G1::projective(g_list[n + 1 - j]).mul_scalar(y[j] * G::Zp::from_u64(x_bits[j]));
    }

    let y_bytes = &*(1..n + 1)
        .flat_map(|i| y[i].to_le_bytes().as_ref().to_vec())
        .collect::<Box<_>>();

    let mut t = vec![G::Zp::ZERO; n];
    G::Zp::hash(
        &mut t,
        &[
            hash_t,
            y_bytes,
            v_hat.to_le_bytes().as_ref(),
            c_hat.to_le_bytes().as_ref(),
            c_y.to_le_bytes().as_ref(),
        ],
    );
    let t = OneBased(t);

    let mut proof_eq = G::G1::ZERO;
    for i in 1..n + 1 {
        let mut numerator = G::G1::projective(g_list[n + 1 - i]).mul_scalar(gamma);
        for j in 1..n + 1 {
            if j != i {
                let term = if x_bits[j] != 0 {
                    G::G1::projective(g_list[n + 1 - i + j])
                } else {
                    G::G1::ZERO
                };
                numerator += term;
            }
        }
        numerator = numerator.mul_scalar(t[i] * y[i]);

        let mut denominator = G::G1::projective(g_list[i]).mul_scalar(gamma_y);
        for j in 1..n + 1 {
            if j != i {
                denominator += G::G1::projective(g_list[n + 1 - j + i])
                    .mul_scalar(y[j] * G::Zp::from_u64(x_bits[j]));
            }
        }
        denominator = denominator.mul_scalar(t[i]);

        proof_eq += numerator - denominator;
    }

    let mut proof_y = g.mul_scalar(gamma_y);
    for j in 1..n + 1 {
        proof_y -=
            G::G1::projective(g_list[n + 1 - j]).mul_scalar(y[j] * G::Zp::from_u64(1 - x_bits[j]));
    }
    proof_y = proof_y.mul_scalar(gamma);
    for i in 1..n + 1 {
        let mut term = G::G1::projective(g_list[i]).mul_scalar(gamma_y);
        for j in 1..n + 1 {
            if j != i {
                term -= G::G1::projective(g_list[n + 1 - j + i])
                    .mul_scalar(y[j] * G::Zp::from_u64(1 - x_bits[j]));
            }
        }
        let term = if x_bits[i] != 0 { term } else { G::G1::ZERO };
        proof_y += term;
    }

    let mut s = vec![G::Zp::ZERO; n];
    for (i, s) in s.iter_mut().enumerate() {
        G::Zp::hash(
            core::slice::from_mut(s),
            &[
                hash_s,
                &(i as u64).to_le_bytes(),
                v_hat.to_le_bytes().as_ref(),
                c_hat.to_le_bytes().as_ref(),
                c_y.to_le_bytes().as_ref(),
            ],
        );
    }
    let s = OneBased(s);

    let mut proof_v = G::G1::ZERO;
    for i in 2..n + 1 {
        proof_v += G::G1::mul_scalar(
            G::G1::projective(g_list[n + 1 - i]).mul_scalar(r)
                + G::G1::projective(g_list[n + 2 - i]).mul_scalar(G::Zp::from_u64(x)),
            s[i],
        );
    }

    let mut delta = [G::Zp::ZERO; 4];
    G::Zp::hash(
        &mut delta,
        &[
            hash_agg,
            v_hat.to_le_bytes().as_ref(),
            c_hat.to_le_bytes().as_ref(),
            c_y.to_le_bytes().as_ref(),
        ],
    );
    let [delta_x, delta_eq, delta_y, delta_v] = delta;

    let proof = proof_x.mul_scalar(delta_x)
        + proof_eq.mul_scalar(delta_eq)
        + proof_y.mul_scalar(delta_y)
        + proof_v.mul_scalar(delta_v);

    Proof {
        c_y,
        c_hat,
        pi: proof,
    }
}

#[allow(clippy::result_unit_err)]
pub fn verify<G: Curve>(
    proof: &Proof<G>,
    public: (&PublicParams<G>, &PublicCommit<G>),
) -> Result<(), ()> {
    let e = G::Gt::pairing;
    let &PublicCommit { l, v_hat } = public.1;
    let PublicParams {
        g_lists,
        hash,
        hash_s,
        hash_t,
        hash_agg,
    } = public.0;
    let n = g_lists.message_len;

    let g_list = &g_lists.g_list;
    let g_hat_list = &g_lists.g_hat_list;

    let g_hat = G::G2::GENERATOR;

    let &Proof { c_y, c_hat, pi } = proof;

    let mut y = vec![G::Zp::ZERO; n];
    G::Zp::hash(
        &mut y,
        &[
            hash,
            v_hat.to_le_bytes().as_ref(),
            c_hat.to_le_bytes().as_ref(),
        ],
    );
    let y = OneBased(y);

    let y_bytes = &*(1..n + 1)
        .flat_map(|i| y[i].to_le_bytes().as_ref().to_vec())
        .collect::<Box<_>>();

    let mut t = vec![G::Zp::ZERO; n];
    G::Zp::hash(
        &mut t,
        &[
            hash_t,
            y_bytes,
            v_hat.to_le_bytes().as_ref(),
            c_hat.to_le_bytes().as_ref(),
            c_y.to_le_bytes().as_ref(),
        ],
    );
    let t = OneBased(t);

    let mut delta = [G::Zp::ZERO; 4];
    G::Zp::hash(
        &mut delta,
        &[
            hash_agg,
            v_hat.to_le_bytes().as_ref(),
            c_hat.to_le_bytes().as_ref(),
            c_y.to_le_bytes().as_ref(),
        ],
    );
    let [delta_x, delta_eq, delta_y, delta_v] = delta;

    let mut s = vec![G::Zp::ZERO; n];
    for (i, s) in s.iter_mut().enumerate() {
        G::Zp::hash(
            core::slice::from_mut(s),
            &[
                hash_s,
                &(i as u64).to_le_bytes(),
                v_hat.to_le_bytes().as_ref(),
                c_hat.to_le_bytes().as_ref(),
                c_y.to_le_bytes().as_ref(),
            ],
        );
    }
    let s = OneBased(s);

    let rhs = e(pi, g_hat);
    let lhs = {
        let numerator = {
            let mut p = c_y.mul_scalar(delta_y);
            for i in 1..n + 1 {
                let g = G::G1::projective(g_list[n + 1 - i]);
                if i <= l {
                    p += g.mul_scalar(delta_x * G::Zp::from_u64(1 << (i - 1)));
                }
                p += g.mul_scalar((delta_eq * t[i] - delta_y) * y[i]);
            }
            e(p, c_hat)
        };
        let denominator_0 = {
            let mut p = G::G1::projective(g_list[n]).mul_scalar(delta_x);
            for i in 2..n + 1 {
                p -= G::G1::projective(g_list[n + 1 - i]).mul_scalar(delta_v * s[i]);
            }
            e(p, v_hat)
        };
        let denominator_1 = {
            let mut q = G::G2::ZERO;
            for i in 1..n + 1 {
                q += G::G2::projective(g_hat_list[i]).mul_scalar(delta_eq * t[i]);
            }
            e(c_y, q)
        };
        numerator - denominator_0 - denominator_1
    };

    if lhs == rhs {
        Ok(())
    } else {
        Err(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{RngExt, SeedableRng};

    #[test]
    fn test_range() {
        let rng = &mut StdRng::seed_from_u64(0);

        let max_nbits = 10;
        let l = 6;
        let x = rng.random::<u64>() % (1 << l);
        let public_params = crs_gen::<crate::curve_api::Bls12_446>(max_nbits, rng);
        let (public_commit, private_commit) = commit(x, l, &public_params, rng);
        let proof = prove((&public_params, &public_commit), &private_commit, rng);
        let verify = verify(&proof, (&public_params, &public_commit));
        assert!(verify.is_ok());
    }
}
