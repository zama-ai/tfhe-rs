use super::*;

#[derive(Clone, Debug)]
pub struct PublicParams<G: Curve> {
    g_lists: GroupElements<G>,
    hash: [u8; LEGACY_HASH_DS_LEN_BYTES],
    hash_t: [u8; LEGACY_HASH_DS_LEN_BYTES],
    hash_agg: [u8; LEGACY_HASH_DS_LEN_BYTES],
}

impl<G: Curve> PublicParams<G> {
    pub fn from_vec(
        g_list: Vec<Affine<G::Zp, G::G1>>,
        g_hat_list: Vec<Affine<G::Zp, G::G2>>,
        hash: [u8; LEGACY_HASH_DS_LEN_BYTES],
        hash_t: [u8; LEGACY_HASH_DS_LEN_BYTES],
        hash_agg: [u8; LEGACY_HASH_DS_LEN_BYTES],
    ) -> Self {
        Self {
            g_lists: GroupElements::from_vec(g_list, g_hat_list),
            hash,
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
    c_hat: G::G2,
}

#[derive(Clone, Debug)]
pub struct PrivateCommit<G: Curve> {
    message: Vec<u64>,
    gamma: G::Zp,
}

#[derive(Clone, Debug)]
pub struct Proof<G: Curve> {
    c_y: G::G1,
    pi: G::G1,
}

pub fn crs_gen<G: Curve>(message_len: usize, rng: &mut impl RngExt) -> PublicParams<G> {
    let alpha = G::Zp::rand(rng);
    PublicParams {
        g_lists: GroupElements::new(message_len, alpha),
        hash: core::array::from_fn(|_| rng.random()),
        hash_t: core::array::from_fn(|_| rng.random()),
        hash_agg: core::array::from_fn(|_| rng.random()),
    }
}

pub fn commit<G: Curve>(
    message: &[u64],
    public: &PublicParams<G>,
    rng: &mut impl RngExt,
) -> (PublicCommit<G>, PrivateCommit<G>) {
    let g_hat = G::G2::GENERATOR;
    let n = message.len();

    let gamma = G::Zp::rand(rng);
    let x = OneBased::new_ref(message);

    let mut c_hat = g_hat.mul_scalar(gamma);
    for j in 1..n + 1 {
        let term = if x[j] != 0 {
            G::G2::projective(public.g_lists.g_hat_list[j])
        } else {
            G::G2::ZERO
        };
        c_hat += term;
    }

    (
        PublicCommit { c_hat },
        PrivateCommit {
            message: message.to_vec(),
            gamma,
        },
    )
}

pub fn prove<G: Curve>(
    public: (&PublicParams<G>, &PublicCommit<G>),
    private_commit: &PrivateCommit<G>,
    rng: &mut impl RngExt,
) -> Proof<G> {
    let n = private_commit.message.len();
    let g = G::G1::GENERATOR;
    let x = OneBased::new_ref(&*private_commit.message);
    let c_hat = public.1.c_hat;
    let gamma = private_commit.gamma;
    let gamma_y = G::Zp::rand(rng);
    let g_list = &public.0.g_lists.g_list;

    let mut y = OneBased(vec![G::Zp::ZERO; n]);
    G::Zp::hash(&mut y.0, &[&public.0.hash, c_hat.to_le_bytes().as_ref()]);

    let mut c_y = g.mul_scalar(gamma_y);
    for j in 1..n + 1 {
        c_y += (G::G1::projective(g_list[n + 1 - j])).mul_scalar(y[j] * G::Zp::from_u64(x[j]));
    }

    let y_bytes = &*(1..n + 1)
        .flat_map(|i| y[i].to_le_bytes().as_ref().to_vec())
        .collect::<Box<_>>();
    let mut t = OneBased(vec![G::Zp::ZERO; n]);
    G::Zp::hash(
        &mut t.0,
        &[
            &public.0.hash_t,
            y_bytes,
            c_hat.to_le_bytes().as_ref(),
            c_y.to_le_bytes().as_ref(),
        ],
    );

    let mut delta = [G::Zp::ZERO; 2];
    G::Zp::hash(
        &mut delta,
        &[
            &public.0.hash_agg,
            c_hat.to_le_bytes().as_ref(),
            c_y.to_le_bytes().as_ref(),
        ],
    );
    let [delta_eq, delta_y] = delta;

    let proof = {
        let mut poly_0 = vec![G::Zp::ZERO; n + 1];
        let mut poly_1 = vec![G::Zp::ZERO; n + 1];
        let mut poly_2 = vec![G::Zp::ZERO; n + 1];
        let mut poly_3 = vec![G::Zp::ZERO; n + 1];

        poly_0[0] = gamma_y * delta_y;
        for i in 1..n + 1 {
            poly_0[n + 1 - i] =
                delta_y * (G::Zp::from_u64(x[i]) * y[i]) + (delta_eq * t[i] - delta_y) * y[i];
        }

        poly_1[0] = gamma;
        for i in 1..n + 1 {
            poly_1[i] = G::Zp::from_u64(x[i]);
        }

        poly_2[0] = gamma_y;
        for i in 1..n + 1 {
            poly_2[n + 1 - i] = y[i] * G::Zp::from_u64(x[i]);
        }

        for i in 1..n + 1 {
            poly_3[i] = delta_eq * t[i];
        }

        let poly = G::Zp::poly_sub(
            &G::Zp::poly_mul(&poly_0, &poly_1),
            &G::Zp::poly_mul(&poly_2, &poly_3),
        );

        let mut proof = g.mul_scalar(poly[0]);
        for i in 1..poly.len() {
            proof += G::G1::projective(g_list[i]).mul_scalar(poly[i]);
        }
        proof
    };

    Proof { pi: proof, c_y }
}

#[allow(clippy::result_unit_err)]
pub fn verify<G: Curve>(
    proof: &Proof<G>,
    public: (&PublicParams<G>, &PublicCommit<G>),
) -> Result<(), ()> {
    let e = G::Gt::pairing;
    let c_hat = public.1.c_hat;
    let g_hat = G::G2::GENERATOR;
    let g_list = &public.0.g_lists.g_list;
    let g_hat_list = &public.0.g_lists.g_hat_list;
    let n = public.0.g_lists.message_len;

    let pi = proof.pi;
    let c_y = proof.c_y;

    let mut y = OneBased(vec![G::Zp::ZERO; n]);
    G::Zp::hash(&mut y.0, &[&public.0.hash, c_hat.to_le_bytes().as_ref()]);

    let y_bytes = &*(1..n + 1)
        .flat_map(|i| y[i].to_le_bytes().as_ref().to_vec())
        .collect::<Box<_>>();
    let mut t = OneBased(vec![G::Zp::ZERO; n]);
    G::Zp::hash(
        &mut t.0,
        &[
            &public.0.hash_t,
            y_bytes,
            c_hat.to_le_bytes().as_ref(),
            c_y.to_le_bytes().as_ref(),
        ],
    );

    let mut delta = [G::Zp::ZERO; 2];
    G::Zp::hash(
        &mut delta,
        &[
            &public.0.hash_agg,
            c_hat.to_le_bytes().as_ref(),
            c_y.to_le_bytes().as_ref(),
        ],
    );
    let [delta_eq, delta_y] = delta;

    let rhs = e(pi, g_hat);
    let lhs = {
        let numerator = {
            let mut p = c_y.mul_scalar(delta_y);
            for i in 1..n + 1 {
                let gy = G::G1::projective(g_list[n + 1 - i]).mul_scalar(y[i]);
                p += gy.mul_scalar(delta_eq).mul_scalar(t[i]) - gy.mul_scalar(delta_y);
            }
            e(p, c_hat)
        };
        let denominator = {
            let mut q = G::G2::ZERO;
            for i in 1..n + 1 {
                q += G::G2::projective(g_hat_list[i])
                    .mul_scalar(delta_eq)
                    .mul_scalar(t[i]);
            }
            e(c_y, q)
        };
        numerator - denominator
    };

    if lhs == rhs {
        Ok(())
    } else {
        Err(())
    }
}
