use rand::RngExt;

use super::*;

#[derive(Clone, Debug)]
pub struct PublicParams<G: Curve> {
    g_lists: GroupElements<G>,
}

impl<G: Curve> PublicParams<G> {
    pub fn from_vec(
        g_list: Vec<Affine<G::Zp, G::G1>>,
        g_hat_list: Vec<Affine<G::Zp, G::G2>>,
    ) -> Self {
        Self {
            g_lists: GroupElements::from_vec(g_list, g_hat_list),
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
    c: G::G1,
}

#[derive(Clone, Debug)]
pub struct PrivateCommit<G: Curve> {
    message: Vec<u64>,
    gamma: G::Zp,
}

#[derive(Clone, Debug)]
pub struct Proof<G: Curve> {
    pi: G::G1,
}

pub fn crs_gen<G: Curve>(message_len: usize, rng: &mut impl RngExt) -> PublicParams<G> {
    let alpha = G::Zp::rand(rng);
    PublicParams {
        g_lists: GroupElements::new(message_len, alpha),
    }
}

pub fn commit<G: Curve>(
    message: &[u64],
    public: &PublicParams<G>,
    rng: &mut impl RngExt,
) -> (PublicCommit<G>, PrivateCommit<G>) {
    let g = G::G1::GENERATOR;
    let n = message.len();

    let gamma = G::Zp::rand(rng);
    let m = OneBased::new_ref(message);

    let mut c = g.mul_scalar(gamma);
    for j in 1..n + 1 {
        let term = G::G1::projective(public.g_lists.g_list[j]).mul_scalar(G::Zp::from_u64(m[j]));
        c += term;
    }

    (
        PublicCommit { c },
        PrivateCommit {
            message: message.to_vec(),
            gamma,
        },
    )
}

pub fn prove<G: Curve>(
    i: usize,
    public: (&PublicParams<G>, &PublicCommit<G>),
    private: &PrivateCommit<G>,
    rng: &mut impl RngExt,
) -> Proof<G> {
    let _ = rng;
    let n = private.message.len();
    let m = OneBased::new_ref(&*private.message);
    let gamma = private.gamma;
    let g_list = &public.0.g_lists.g_list;

    let mut pi = G::G1::projective(g_list[n + 1 - i]).mul_scalar(gamma);
    for j in 1..n + 1 {
        if i != j {
            let term = if m[j] & 1 == 1 {
                G::G1::projective(g_list[n + 1 - i + j])
            } else {
                G::G1::ZERO
            };

            pi += term;
        }
    }

    Proof { pi }
}

#[allow(clippy::result_unit_err)]
pub fn verify<G: Curve>(
    proof: &Proof<G>,
    (index, mi): (usize, u64),
    public: (&PublicParams<G>, &PublicCommit<G>),
) -> Result<(), ()> {
    let e = G::Gt::pairing;
    let c = public.1.c;
    let g_hat = G::G2::GENERATOR;
    let g_list = &public.0.g_lists.g_list;
    let g_hat_list = &public.0.g_lists.g_hat_list;
    let n = public.0.g_lists.message_len;
    let i = index + 1;

    let lhs = e(c, G::G2::projective(g_hat_list[n + 1 - i]));
    let rhs = e(proof.pi, g_hat)
        + (e(
            G::G1::projective(g_list[1]),
            G::G2::projective(g_hat_list[n]),
        ))
        .mul_scalar(G::Zp::from_u64(mi));

    if lhs == rhs {
        Ok(())
    } else {
        Err(())
    }
}
