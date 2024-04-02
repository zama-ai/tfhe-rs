use super::*;

/// multiply EC point with scalar (= exponentiation in multiplicative notation)
fn mul_zp<T: Copy + Zero + Add<Output = T> + Group>(x: T, scalar: Zp) -> T {
    let zero = T::zero();
    let n: BigInt<5> = scalar.inner.into();

    if n == BigInt([0; 5]) {
        return zero;
    }

    let mut y = zero;
    let mut x = x;

    let n = n.0;
    for word in n {
        for idx in 0..64 {
            let bit = (word >> idx) & 1;
            if bit == 1 {
                y += x;
            }
            x.double_in_place();
        }
    }
    y
}

fn bigint_to_bytes(x: [u64; 7]) -> [u8; 7 * 8] {
    let mut buf = [0u8; 7 * 8];
    for (i, &xi) in x.iter().enumerate() {
        buf[i * 8..][..8].copy_from_slice(&xi.to_le_bytes());
    }
    buf
}

mod g1 {
    use super::*;

    #[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
    #[repr(transparent)]
    pub struct G1 {
        #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
        pub(crate) inner: crate::curve_446::g1::G1Projective,
    }

    impl fmt::Debug for G1 {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("G1")
                .field("x", &MontIntDisplay(&self.inner.x))
                .field("y", &MontIntDisplay(&self.inner.y))
                .field("z", &MontIntDisplay(&self.inner.z))
                .finish()
        }
    }

    impl G1 {
        pub const ZERO: Self = Self {
            inner: crate::curve_446::g1::G1Projective {
                x: MontFp!("1"),
                y: MontFp!("1"),
                z: MontFp!("0"),
            },
        };

        pub const GENERATOR: Self = Self {
            inner: crate::curve_446::g1::G1Projective {
                x: MontFp!("143189966182216199425404656824735381247272236095050141599848381692039676741476615087722874458136990266833440576646963466074693171606778"),
                y: MontFp!("75202396197342917254523279069469674666303680671605970245803554133573745859131002231546341942288521574682619325841484506619191207488304"),
                z: MontFp!("1"),
            },
        };

        // Size in number of bytes when the [to_bytes]
        // function is called.
        // This is not the size after serialization!
        pub const BYTE_SIZE: usize = 2 * 7 * 8 + 1;

        pub fn mul_scalar(self, scalar: Zp) -> Self {
            Self {
                inner: mul_zp(self.inner, scalar),
            }
        }

        pub fn multi_mul_scalar(bases: &[Self], scalars: &[Zp]) -> Self {
            use rayon::prelude::*;
            let n_threads = rayon::current_num_threads();
            let chunk_size = bases.len().div_ceil(n_threads);
            bases
                .par_iter()
                .map(|&x| x.inner.into_affine())
                .chunks(chunk_size)
                .zip(scalars.par_iter().map(|&x| x.inner).chunks(chunk_size))
                .map(|(bases, scalars)| Self {
                    inner: crate::curve_446::g1::G1Projective::msm(&bases, &scalars).unwrap(),
                })
                .sum::<Self>()
        }

        pub fn to_bytes(self) -> [u8; Self::BYTE_SIZE] {
            let g = self.inner.into_affine();
            let x = bigint_to_bytes(g.x.0 .0);
            let y = bigint_to_bytes(g.y.0 .0);
            let mut buf = [0u8; 2 * 7 * 8 + 1];
            buf[..7 * 8].copy_from_slice(&x);
            buf[7 * 8..][..7 * 8].copy_from_slice(&y);
            buf[2 * 7 * 8] = g.infinity as u8;
            buf
        }

        pub fn double(self) -> Self {
            Self {
                inner: self.inner.double(),
            }
        }
    }

    impl Add for G1 {
        type Output = G1;

        #[inline]
        fn add(self, rhs: Self) -> Self::Output {
            G1 {
                inner: self.inner + rhs.inner,
            }
        }
    }

    impl Sub for G1 {
        type Output = G1;

        #[inline]
        fn sub(self, rhs: Self) -> Self::Output {
            G1 {
                inner: self.inner - rhs.inner,
            }
        }
    }

    impl AddAssign for G1 {
        #[inline]
        fn add_assign(&mut self, rhs: Self) {
            self.inner += rhs.inner
        }
    }

    impl SubAssign for G1 {
        #[inline]
        fn sub_assign(&mut self, rhs: Self) {
            self.inner -= rhs.inner
        }
    }

    impl core::iter::Sum for G1 {
        fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
            iter.fold(G1::ZERO, Add::add)
        }
    }

    impl Neg for G1 {
        type Output = Self;

        fn neg(self) -> Self::Output {
            Self { inner: -self.inner }
        }
    }
}

mod g2 {
    use super::*;

    #[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
    #[repr(transparent)]
    pub struct G2 {
        #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
        pub(super) inner: crate::curve_446::g2::G2Projective,
    }

    impl fmt::Debug for G2 {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            #[allow(dead_code)]
            #[derive(Debug)]
            struct QuadExtField<T> {
                c0: T,
                c1: T,
            }

            f.debug_struct("G2")
                .field(
                    "x",
                    &QuadExtField {
                        c0: MontIntDisplay(&self.inner.x.c0),
                        c1: MontIntDisplay(&self.inner.x.c1),
                    },
                )
                .field(
                    "y",
                    &QuadExtField {
                        c0: MontIntDisplay(&self.inner.y.c0),
                        c1: MontIntDisplay(&self.inner.y.c1),
                    },
                )
                .field(
                    "z",
                    &QuadExtField {
                        c0: MontIntDisplay(&self.inner.z.c0),
                        c1: MontIntDisplay(&self.inner.z.c1),
                    },
                )
                .finish()
        }
    }

    impl G2 {
        pub const ZERO: Self = Self {
            inner: crate::curve_446::g2::G2Projective {
                x: ark_ff::QuadExtField {
                    c0: MontFp!("1"),
                    c1: MontFp!("0"),
                },
                y: ark_ff::QuadExtField {
                    c0: MontFp!("1"),
                    c1: MontFp!("0"),
                },
                z: ark_ff::QuadExtField {
                    c0: MontFp!("0"),
                    c1: MontFp!("0"),
                },
            },
        };

        pub const GENERATOR: Self = Self {
            inner: crate::curve_446::g2::G2Projective {
                x: ark_ff::QuadExtField {
                    c0: MontFp!("96453755443802578867745476081903764610578492683850270111202389209355548711427786327510993588141991264564812146530214503491136289085725"),
                    c1: MontFp!("85346509177292795277012009839788781950274202400882571466460158277083221521663169974265433098009350061415973662678938824527658049065530"),
                },
                y: ark_ff::QuadExtField {
                    c0: MontFp!("49316184343270950587272132771103279293158283984999436491292404103501221698714795975575879957605051223501287444864258801515822358837529"),
                    c1: MontFp!("107680854723992552431070996218129928499826544031468382031848626814251381379173928074140221537929995580031433096217223703806029068859074"),
                },
                z: ark_ff::QuadExtField {
                    c0: MontFp!("1"),
                    c1: MontFp!("0") ,
                },
            },
        };

        // Size in number of bytes when the [to_bytes]
        // function is called.
        // This is not the size after serialization!
        pub const BYTE_SIZE: usize = 4 * 7 * 8 + 1;

        pub fn mul_scalar(self, scalar: Zp) -> Self {
            Self {
                inner: mul_zp(self.inner, scalar),
            }
        }

        pub fn multi_mul_scalar(bases: &[Self], scalars: &[Zp]) -> Self {
            use rayon::prelude::*;
            let n_threads = rayon::current_num_threads();
            let chunk_size = bases.len().div_ceil(n_threads);
            bases
                .par_iter()
                .map(|&x| x.inner.into_affine())
                .chunks(chunk_size)
                .zip(scalars.par_iter().map(|&x| x.inner).chunks(chunk_size))
                .map(|(bases, scalars)| Self {
                    inner: crate::curve_446::g2::G2Projective::msm(&bases, &scalars).unwrap(),
                })
                .sum::<Self>()
        }

        pub fn to_bytes(self) -> [u8; Self::BYTE_SIZE] {
            let g = self.inner.into_affine();
            let xc0 = bigint_to_bytes(g.x.c0.0 .0);
            let xc1 = bigint_to_bytes(g.x.c1.0 .0);
            let yc0 = bigint_to_bytes(g.y.c0.0 .0);
            let yc1 = bigint_to_bytes(g.y.c1.0 .0);
            let mut buf = [0u8; 4 * 7 * 8 + 1];
            buf[..7 * 8].copy_from_slice(&xc0);
            buf[7 * 8..][..7 * 8].copy_from_slice(&xc1);
            buf[2 * 7 * 8..][..7 * 8].copy_from_slice(&yc0);
            buf[3 * 7 * 8..][..7 * 8].copy_from_slice(&yc1);
            buf[4 * 7 * 8] = g.infinity as u8;
            buf
        }

        pub fn double(self) -> Self {
            Self {
                inner: self.inner.double(),
            }
        }
    }

    impl Add for G2 {
        type Output = G2;

        #[inline]
        fn add(self, rhs: Self) -> Self::Output {
            G2 {
                inner: self.inner + rhs.inner,
            }
        }
    }

    impl Sub for G2 {
        type Output = G2;

        #[inline]
        fn sub(self, rhs: Self) -> Self::Output {
            G2 {
                inner: self.inner - rhs.inner,
            }
        }
    }

    impl AddAssign for G2 {
        #[inline]
        fn add_assign(&mut self, rhs: Self) {
            self.inner += rhs.inner
        }
    }

    impl SubAssign for G2 {
        #[inline]
        fn sub_assign(&mut self, rhs: Self) {
            self.inner -= rhs.inner
        }
    }

    impl core::iter::Sum for G2 {
        fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
            iter.fold(G2::ZERO, Add::add)
        }
    }

    impl Neg for G2 {
        type Output = Self;

        fn neg(self) -> Self::Output {
            Self { inner: -self.inner }
        }
    }
}

mod gt {
    use super::*;
    use ark_ec::bls12::Bls12Config;
    use ark_ec::pairing::{MillerLoopOutput, Pairing};
    use ark_ff::{CubicExtField, Fp12, Fp2, QuadExtField};

    type Bls = crate::curve_446::Bls12_446;
    type Config = crate::curve_446::Config;

    const ONE: Fp2<<Config as Bls12Config>::Fp2Config> = QuadExtField {
        c0: MontFp!("1"),
        c1: MontFp!("0"),
    };
    const ZERO: Fp2<<Config as Bls12Config>::Fp2Config> = QuadExtField {
        c0: MontFp!("0"),
        c1: MontFp!("0"),
    };

    const U1: Fp12<<Config as Bls12Config>::Fp12Config> = QuadExtField {
        c0: CubicExtField {
            c0: ZERO,
            c1: ZERO,
            c2: ZERO,
        },
        c1: CubicExtField {
            c0: ONE,
            c1: ZERO,
            c2: ZERO,
        },
    };
    const U3: Fp12<<Config as Bls12Config>::Fp12Config> = QuadExtField {
        c0: CubicExtField {
            c0: ZERO,
            c1: ZERO,
            c2: ZERO,
        },
        c1: CubicExtField {
            c0: ZERO,
            c1: ONE,
            c2: ZERO,
        },
    };

    const fn fp2_to_fp12(
        x: Fp2<<Config as Bls12Config>::Fp2Config>,
    ) -> Fp12<<Config as Bls12Config>::Fp12Config> {
        QuadExtField {
            c0: CubicExtField {
                c0: x,
                c1: ZERO,
                c2: ZERO,
            },
            c1: CubicExtField {
                c0: ZERO,
                c1: ZERO,
                c2: ZERO,
            },
        }
    }

    const fn fp_to_fp12(
        x: <Config as Bls12Config>::Fp,
    ) -> Fp12<<Config as Bls12Config>::Fp12Config> {
        fp2_to_fp12(QuadExtField {
            c0: x,
            c1: MontFp!("0"),
        })
    }

    fn ate_tangent_ev(qt: G2, evpt: G1) -> Fp12<<Config as Bls12Config>::Fp12Config> {
        let qt = qt.inner.into_affine();
        let evpt = evpt.inner.into_affine();

        let (xt, yt) = (qt.x, qt.y);
        let (xe, ye) = (evpt.x, evpt.y);

        let xt = fp2_to_fp12(xt);
        let yt = fp2_to_fp12(yt);
        let xe = fp_to_fp12(xe);
        let ye = fp_to_fp12(ye);

        let three = fp_to_fp12(MontFp!("3"));
        let two = fp_to_fp12(MontFp!("2"));

        let l = three * xt.square() / (two * yt);
        ye - (l * xe) / U1 + (l * xt - yt) / U3
    }

    fn ate_line_ev(q1: G2, q2: G2, evpt: G1) -> Fp12<<Config as Bls12Config>::Fp12Config> {
        let q1 = q1.inner.into_affine();
        let q2 = q2.inner.into_affine();
        let evpt = evpt.inner.into_affine();

        let (x1, y1) = (q1.x, q1.y);
        let (x2, y2) = (q2.x, q2.y);
        let (xe, ye) = (evpt.x, evpt.y);

        let x1 = fp2_to_fp12(x1);
        let y1 = fp2_to_fp12(y1);
        let x2 = fp2_to_fp12(x2);
        let y2 = fp2_to_fp12(y2);
        let xe = fp_to_fp12(xe);
        let ye = fp_to_fp12(ye);

        let l = (y2 - y1) / (x2 - x1);
        ye - (l * xe) / U1 + (l * x1 - y1) / U3
    }

    #[allow(clippy::needless_range_loop)]
    fn ate_pairing(p: G1, q: G2) -> Gt {
        let t_log2 = 75;
        let t_bits = b"110000000001000001000000100000000000000000000000000000000100000000000000001";

        let mut fk = fp_to_fp12(MontFp!("1"));
        let mut qk = q;

        for k in 1..t_log2 {
            let lkk = ate_tangent_ev(qk, p);
            qk = qk + qk;
            fk = fk.square() * lkk;

            if t_bits[k] == b'1' {
                assert_ne!(q, qk);
                let lkp1 = if q != -qk {
                    ate_line_ev(q, qk, p)
                } else {
                    fp_to_fp12(MontFp!("1"))
                };
                qk += q;
                fk *= lkp1;
            }
        }
        let mlo = MillerLoopOutput(fk);
        Gt {
            inner: Bls::final_exponentiation(mlo).unwrap(),
        }
    }

    #[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
    #[repr(transparent)]
    pub struct Gt {
        #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
        pub(crate) inner: ark_ec::pairing::PairingOutput<crate::curve_446::Bls12_446>,
    }

    impl fmt::Debug for Gt {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            #[allow(dead_code)]
            #[derive(Debug)]
            struct QuadExtField<T> {
                c0: T,
                c1: T,
            }

            #[allow(dead_code)]
            #[derive(Debug)]
            struct CubicExtField<T> {
                c0: T,
                c1: T,
                c2: T,
            }

            #[allow(dead_code)]
            #[derive(Debug)]
            pub struct Gt<T> {
                inner: T,
            }

            f.debug_struct("Gt")
                .field(
                    "inner",
                    &Gt {
                        inner: QuadExtField {
                            c0: CubicExtField {
                                c0: QuadExtField {
                                    c0: MontIntDisplay(&self.inner.0.c0.c0.c0),
                                    c1: MontIntDisplay(&self.inner.0.c0.c0.c1),
                                },
                                c1: QuadExtField {
                                    c0: MontIntDisplay(&self.inner.0.c0.c1.c0),
                                    c1: MontIntDisplay(&self.inner.0.c0.c1.c1),
                                },
                                c2: QuadExtField {
                                    c0: MontIntDisplay(&self.inner.0.c0.c2.c0),
                                    c1: MontIntDisplay(&self.inner.0.c0.c2.c1),
                                },
                            },
                            c1: CubicExtField {
                                c0: QuadExtField {
                                    c0: MontIntDisplay(&self.inner.0.c1.c0.c0),
                                    c1: MontIntDisplay(&self.inner.0.c1.c0.c1),
                                },
                                c1: QuadExtField {
                                    c0: MontIntDisplay(&self.inner.0.c1.c1.c0),
                                    c1: MontIntDisplay(&self.inner.0.c1.c1.c1),
                                },
                                c2: QuadExtField {
                                    c0: MontIntDisplay(&self.inner.0.c1.c2.c0),
                                    c1: MontIntDisplay(&self.inner.0.c1.c2.c1),
                                },
                            },
                        },
                    },
                )
                .finish()
        }
    }

    impl Gt {
        pub fn pairing(g1: G1, g2: G2) -> Self {
            ate_pairing(g1, -g2)
        }

        pub fn mul_scalar(self, scalar: Zp) -> Self {
            Self {
                inner: mul_zp(self.inner, scalar),
            }
        }
    }

    impl Add for Gt {
        type Output = Gt;

        #[inline]
        fn add(self, rhs: Self) -> Self::Output {
            Gt {
                inner: self.inner + rhs.inner,
            }
        }
    }

    impl Sub for Gt {
        type Output = Gt;

        #[inline]
        fn sub(self, rhs: Self) -> Self::Output {
            Gt {
                inner: self.inner - rhs.inner,
            }
        }
    }

    impl AddAssign for Gt {
        #[inline]
        fn add_assign(&mut self, rhs: Self) {
            self.inner += rhs.inner
        }
    }

    impl SubAssign for Gt {
        #[inline]
        fn sub_assign(&mut self, rhs: Self) {
            self.inner -= rhs.inner
        }
    }

    impl Neg for Gt {
        type Output = Self;

        fn neg(self) -> Self::Output {
            Self { inner: -self.inner }
        }
    }
}

mod zp {
    use super::*;
    use ark_ff::Fp;
    use zeroize::Zeroize;

    fn redc(n: [u64; 5], nprime: u64, mut t: [u64; 7]) -> [u64; 5] {
        for i in 0..2 {
            let mut c = 0u64;
            let m = u64::wrapping_mul(t[i], nprime);

            for j in 0..5 {
                let x = t[i + j] as u128 + m as u128 * n[j] as u128 + c as u128;
                t[i + j] = x as u64;
                c = (x >> 64) as u64;
            }

            for j in 5..7 - i {
                let x = t[i + j] as u128 + c as u128;
                t[i + j] = x as u64;
                c = (x >> 64) as u64;
            }
        }

        let mut t = [t[2], t[3], t[4], t[5], t[6]];

        if t.into_iter().rev().ge(n.into_iter().rev()) {
            let mut o = false;
            for i in 0..5 {
                let (ti, o0) = u64::overflowing_sub(t[i], n[i]);
                let (ti, o1) = u64::overflowing_sub(ti, o as u64);
                o = o0 | o1;
                t[i] = ti;
            }
        }
        assert!(t.into_iter().rev().lt(n.into_iter().rev()));

        t
    }

    #[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Hash, Zeroize)]
    #[repr(transparent)]
    pub struct Zp {
        #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
        pub(crate) inner: crate::curve_446::Fr,
    }

    impl fmt::Debug for Zp {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_tuple("Zp")
                .field(&MontIntDisplay(&self.inner))
                .finish()
        }
    }

    impl Zp {
        pub const ZERO: Self = Self {
            inner: MontFp!("0"),
        };

        pub const ONE: Self = Self {
            inner: MontFp!("1"),
        };

        pub fn from_bigint(n: [u64; 5]) -> Self {
            Self {
                inner: BigInt(n).into(),
            }
        }

        pub fn from_u64(n: u64) -> Self {
            Self {
                inner: BigInt([n, 0, 0, 0, 0]).into(),
            }
        }

        pub fn from_i64(n: i64) -> Self {
            let n_abs = Self::from_u64(n.unsigned_abs());
            if n > 0 {
                n_abs
            } else {
                -n_abs
            }
        }

        pub fn to_bytes(self) -> [u8; 5 * 8] {
            let buf = [
                self.inner.0 .0[0].to_le_bytes(),
                self.inner.0 .0[1].to_le_bytes(),
                self.inner.0 .0[2].to_le_bytes(),
                self.inner.0 .0[3].to_le_bytes(),
                self.inner.0 .0[4].to_le_bytes(),
            ];
            unsafe { core::mem::transmute(buf) }
        }

        fn from_raw_u64x7(n: [u64; 7]) -> Self {
            const MODULUS: BigInt<5> = BigInt!(
                "645383785691237230677916041525710377746967055506026847120930304831624105190538527824412673"
            );

            const MODULUS_MONTGOMERY: u64 = 272467794636046335;

            let mut n = n;
            // zero the 22 leading bits, so the result is <= MODULUS * 2^128
            n[6] &= (1 << 42) - 1;
            Zp {
                inner: Fp(
                    BigInt(redc(MODULUS.0, MODULUS_MONTGOMERY, n)),
                    core::marker::PhantomData,
                ),
            }
        }

        pub fn rand(rng: &mut dyn rand::RngCore) -> Self {
            use rand::Rng;

            Self::from_raw_u64x7([
                rng.gen::<u64>(),
                rng.gen::<u64>(),
                rng.gen::<u64>(),
                rng.gen::<u64>(),
                rng.gen::<u64>(),
                rng.gen::<u64>(),
                rng.gen::<u64>(),
            ])
        }

        pub fn hash(values: &mut [Zp], data: &[&[u8]]) {
            use sha3::digest::{ExtendableOutput, Update, XofReader};

            let mut hasher = sha3::Shake256::default();
            for data in data {
                hasher.update(data);
            }
            let mut reader = hasher.finalize_xof();

            for value in values {
                let mut bytes = [0u8; 7 * 8];
                reader.read(&mut bytes);
                let bytes: [[u8; 8]; 7] = unsafe { core::mem::transmute(bytes) };
                *value = Zp::from_raw_u64x7(bytes.map(u64::from_le_bytes));
            }
        }
    }

    impl Add for Zp {
        type Output = Zp;

        #[inline]
        fn add(self, rhs: Self) -> Self::Output {
            Zp {
                inner: self.inner + rhs.inner,
            }
        }
    }

    impl Sub for Zp {
        type Output = Zp;

        #[inline]
        fn sub(self, rhs: Self) -> Self::Output {
            Zp {
                inner: self.inner - rhs.inner,
            }
        }
    }

    impl Mul for Zp {
        type Output = Zp;

        #[inline]
        fn mul(self, rhs: Self) -> Self::Output {
            Zp {
                inner: self.inner * rhs.inner,
            }
        }
    }

    impl Div for Zp {
        type Output = Zp;

        #[inline]
        fn div(self, rhs: Self) -> Self::Output {
            Zp {
                inner: self.inner / rhs.inner,
            }
        }
    }
    impl AddAssign for Zp {
        #[inline]
        fn add_assign(&mut self, rhs: Self) {
            self.inner += rhs.inner
        }
    }

    impl SubAssign for Zp {
        #[inline]
        fn sub_assign(&mut self, rhs: Self) {
            self.inner -= rhs.inner
        }
    }

    impl Neg for Zp {
        type Output = Self;

        fn neg(self) -> Self::Output {
            Self { inner: -self.inner }
        }
    }

    impl core::iter::Sum for Zp {
        fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
            iter.fold(Zp::ZERO, Add::add)
        }
    }
}

pub use g1::G1;
pub use g2::G2;
pub use gt::Gt;
pub use zp::Zp;

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use std::collections::HashMap;

    #[test]
    fn test_g1() {
        let x = G1::GENERATOR;
        let y = x.mul_scalar(Zp::from_i64(-2) * Zp::from_u64(2));
        assert_eq!(x - x, G1::ZERO);
        assert_eq!(x + y - x, y);
    }

    #[test]
    fn test_g2() {
        let x = G2::GENERATOR;
        let y = x.mul_scalar(Zp::from_i64(-2) * Zp::from_u64(2));
        assert_eq!(x - x, G2::ZERO);
        assert_eq!(x + y - x, y);
    }

    #[test]
    fn test_g1_msm() {
        let n = 1024;
        let x = vec![G1::GENERATOR.mul_scalar(Zp::from_i64(-1)); n];
        let mut p = vec![Zp::ZERO; n];
        Zp::hash(&mut p, &[&[0]]);

        let result = G1::multi_mul_scalar(&x, &p);
        let expected = x
            .iter()
            .zip(p.iter())
            .map(|(&x, &p)| x.mul_scalar(p))
            .sum::<G1>();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_g2_msm() {
        let n = 1024;
        let x = vec![G2::GENERATOR.mul_scalar(Zp::from_i64(-1)); n];
        let mut p = vec![Zp::ZERO; n];
        Zp::hash(&mut p, &[&[0]]);

        let result = G2::multi_mul_scalar(&x, &p);
        let expected = x
            .iter()
            .zip(p.iter())
            .map(|(&x, &p)| x.mul_scalar(p))
            .sum::<G2>();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_pairing() {
        let rng = &mut StdRng::seed_from_u64(0);
        let p1 = Zp::rand(rng);
        let p2 = Zp::rand(rng);

        let x1 = G1::GENERATOR.mul_scalar(p1);
        let x2 = G2::GENERATOR.mul_scalar(p2);

        assert_eq!(
            Gt::pairing(x1, x2),
            Gt::pairing(G1::GENERATOR, G2::GENERATOR).mul_scalar(p1 * p2),
        );
    }

    #[test]
    fn test_distributivity() {
        let a = Zp {
            inner: MontFp!(
                "20799633726231143268782044631117354647259165363910905818134484248029981143850"
            ),
        };
        let b = Zp {
            inner: MontFp!(
                "42333504039292951860879669847432876299949385605895551964353185488509497658948"
            ),
        };
        let c = Zp {
            inner: MontFp!(
                "6797004509292554067788526429737434481164547177696793280652530849910670196287"
            ),
        };

        assert_eq!((((a - b) * c) - (a * c - b * c)).inner, Zp::ZERO.inner);
    }

    #[test]
    fn test_serialization() {
        let rng = &mut StdRng::seed_from_u64(0);
        let alpha = Zp::rand(rng);
        let g_cur = G1::GENERATOR.mul_scalar(alpha);
        let g_hat_cur = G2::GENERATOR.mul_scalar(alpha);

        let alpha2: Zp = serde_json::from_str(&serde_json::to_string(&alpha).unwrap()).unwrap();
        assert_eq!(alpha, alpha2);

        let g_cur2: G1 = serde_json::from_str(&serde_json::to_string(&g_cur).unwrap()).unwrap();
        assert_eq!(g_cur, g_cur2);

        let g_hat_cur2: G2 =
            serde_json::from_str(&serde_json::to_string(&g_hat_cur).unwrap()).unwrap();
        assert_eq!(g_hat_cur, g_hat_cur2);
    }

    #[test]
    fn test_hasher_and_eq() {
        // we need to make sure if the points are the same
        // but the projective representations are different
        // then they still hash into the same thing
        let rng = &mut StdRng::seed_from_u64(0);
        let alpha = Zp::rand(rng);
        let a = G1::GENERATOR.mul_scalar(alpha);

        // serialization should convert the point to affine representation
        // after deserializing it we should have the same point
        // but with a different representation
        let a_affine: G1 = serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap();

        // the internal elements should be different
        assert_ne!(a.inner.x, a_affine.inner.x);
        assert_ne!(a.inner.y, a_affine.inner.y);
        assert_ne!(a.inner.z, a_affine.inner.z);

        // but equality and hasher should see the two as the same point
        assert_eq!(a, a_affine);
        let mut hm = HashMap::new();
        hm.insert(a, 1);
        assert_eq!(hm.len(), 1);
        hm.insert(a_affine, 2);
        assert_eq!(hm.len(), 1);
    }
}
