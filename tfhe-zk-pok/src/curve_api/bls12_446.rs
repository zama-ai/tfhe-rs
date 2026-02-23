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

fn bigint_to_le_bytes(x: [u64; 7]) -> [u8; 7 * 8] {
    let mut buf = [0u8; 7 * 8];
    for (i, &xi) in x.iter().enumerate() {
        buf[i * 8..][..8].copy_from_slice(&xi.to_le_bytes());
    }
    buf
}

mod g1 {
    use tfhe_versionable::Versionize;

    use crate::serialization::{InvalidSerializedAffineError, SerializableG1Affine};

    use super::*;

    #[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash, Versionize)]
    #[serde(try_from = "SerializableG1Affine", into = "SerializableG1Affine")]
    #[versionize(try_from = "SerializableG1Affine", into = "SerializableG1Affine")]
    #[repr(transparent)]
    pub struct G1Affine {
        pub(crate) inner: crate::curve_446::g1::G1Affine,
    }

    impl From<G1Affine> for SerializableAffine<SerializableFp> {
        fn from(value: G1Affine) -> Self {
            SerializableAffine::uncompressed(value.inner)
        }
    }

    impl TryFrom<SerializableAffine<SerializableFp>> for G1Affine {
        type Error = InvalidSerializedAffineError;

        fn try_from(value: SerializableAffine<SerializableFp>) -> Result<Self, Self::Error> {
            Ok(Self {
                inner: value.try_into()?,
            })
        }
    }

    impl Compressible for G1Affine {
        type Compressed = SerializableG1Affine;

        type UncompressError = InvalidSerializedAffineError;

        fn compress(&self) -> Self::Compressed {
            SerializableAffine::compressed(self.inner)
        }

        fn uncompress(compressed: Self::Compressed) -> Result<Self, Self::UncompressError> {
            compressed.try_into()
        }
    }

    impl G1Affine {
        #[track_caller]
        pub fn multi_mul_scalar(bases: &[Self], scalars: &[Zp]) -> G1 {
            // SAFETY: interpreting a `repr(transparent)` pointer as its contents.
            G1 {
                inner: crate::curve_446::g1::G1Projective::msm(
                    unsafe {
                        &*(bases as *const [G1Affine] as *const [crate::curve_446::g1::G1Affine])
                    },
                    unsafe { &*(scalars as *const [Zp] as *const [crate::curve_446::Fr]) },
                )
                .unwrap(),
            }
        }

        pub fn validate(&self) -> bool {
            self.inner.is_on_curve() && self.inner.is_in_correct_subgroup_assuming_on_curve()
        }
    }

    #[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Hash, Versionize)]
    #[serde(try_from = "SerializableG1Affine", into = "SerializableG1Affine")]
    #[versionize(try_from = "SerializableG1Affine", into = "SerializableG1Affine")]
    #[repr(transparent)]
    pub struct G1 {
        pub(crate) inner: crate::curve_446::g1::G1Projective,
    }

    impl From<G1> for SerializableG1Affine {
        fn from(value: G1) -> Self {
            SerializableAffine::uncompressed(value.inner.into_affine())
        }
    }

    impl TryFrom<SerializableG1Affine> for G1 {
        type Error = InvalidSerializedAffineError;

        fn try_from(value: SerializableG1Affine) -> Result<Self, Self::Error> {
            Ok(Self {
                inner: Affine::try_from(value)?.into(),
            })
        }
    }

    impl Compressible for G1 {
        type Compressed = SerializableG1Affine;

        type UncompressError = InvalidSerializedAffineError;

        fn compress(&self) -> Self::Compressed {
            SerializableAffine::compressed(self.inner.into_affine())
        }

        fn uncompress(compressed: Self::Compressed) -> Result<Self, Self::UncompressError> {
            compressed.try_into()
        }
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

        // Size in number of bytes when the [to_le_bytes]
        // function is called.
        // This is not the size after serialization!
        pub const BYTE_SIZE: usize = 2 * 7 * 8 + 1;

        pub fn mul_scalar(self, scalar: Zp) -> Self {
            Self {
                inner: mul_zp(self.inner, scalar),
            }
        }

        pub fn mul_scalar_zeroize(self, scalar: &ZeroizeZp) -> Self {
            Self {
                inner: scalar.mul_point(self.inner),
            }
        }

        #[track_caller]
        pub fn multi_mul_scalar(bases: &[Self], scalars: &[Zp]) -> Self {
            use rayon::prelude::*;
            let bases = bases
                .par_iter()
                .map(|&x| x.inner.into_affine())
                .collect::<Vec<_>>();
            // SAFETY: interpreting a `repr(transparent)` pointer as its contents.
            Self {
                inner: crate::curve_446::g1::G1Projective::msm(&bases, unsafe {
                    &*(scalars as *const [Zp] as *const [crate::curve_446::Fr])
                })
                .unwrap(),
            }
        }

        pub fn to_le_bytes(self) -> [u8; Self::BYTE_SIZE] {
            let g = self.inner.into_affine();
            let x = bigint_to_le_bytes(g.x.0 .0);
            let y = bigint_to_le_bytes(g.y.0 .0);
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
    use tfhe_versionable::Versionize;

    use crate::serialization::SerializableG2Affine;

    use super::*;
    use crate::serialization::InvalidSerializedAffineError;

    #[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash, Versionize)]
    #[serde(try_from = "SerializableG2Affine", into = "SerializableG2Affine")]
    #[versionize(try_from = "SerializableG2Affine", into = "SerializableG2Affine")]
    #[repr(transparent)]
    pub struct G2Affine {
        pub(crate) inner: crate::curve_446::g2::G2Affine,
    }

    impl From<G2Affine> for SerializableG2Affine {
        fn from(value: G2Affine) -> Self {
            SerializableAffine::uncompressed(value.inner)
        }
    }

    impl TryFrom<SerializableG2Affine> for G2Affine {
        type Error = InvalidSerializedAffineError;

        fn try_from(value: SerializableG2Affine) -> Result<Self, Self::Error> {
            Ok(Self {
                inner: value.try_into()?,
            })
        }
    }

    impl Compressible for G2Affine {
        type Compressed = SerializableG2Affine;

        type UncompressError = InvalidSerializedAffineError;

        fn compress(&self) -> Self::Compressed {
            SerializableAffine::compressed(self.inner)
        }

        fn uncompress(compressed: Self::Compressed) -> Result<Self, Self::UncompressError> {
            compressed.try_into()
        }
    }

    impl G2Affine {
        #[track_caller]
        pub fn multi_mul_scalar(bases: &[Self], scalars: &[Zp]) -> G2 {
            // SAFETY: interpreting a `repr(transparent)` pointer as its contents.
            G2 {
                inner: crate::curve_446::g2::G2Projective::msm(
                    unsafe {
                        &*(bases as *const [G2Affine] as *const [crate::curve_446::g2::G2Affine])
                    },
                    unsafe { &*(scalars as *const [Zp] as *const [crate::curve_446::Fr]) },
                )
                .unwrap(),
            }
        }

        pub fn validate(&self) -> bool {
            self.inner.is_on_curve() && self.inner.is_in_correct_subgroup_assuming_on_curve()
        }

        // m is an intermediate variable that's used in both the curve point addition and pairing
        // functions. we cache it since it requires a Zp division
        // https://hackmd.io/@tazAymRSQCGXTUKkbh1BAg/Sk27liTW9#Math-Formula-for-Point-Addition
        pub(crate) fn compute_m(self, other: G2Affine) -> Option<crate::curve_446::Fq2> {
            // in the context of elliptic curves, the point at infinity is the zero element of the
            // group
            let zero = crate::curve_446::Fq2::ZERO;

            if self.inner.infinity || other.inner.infinity {
                return None;
            }

            if self == other {
                let x = self.inner.x;
                let y = self.inner.y;
                if y == zero {
                    None
                } else {
                    let xx = x.square();
                    Some((xx.double() + xx) / y.double())
                }
            } else {
                let x1 = self.inner.x;
                let y1 = self.inner.y;
                let x2 = other.inner.x;
                let y2 = other.inner.y;

                let x_delta = x2 - x1;
                let y_delta = y2 - y1;

                if x_delta == zero {
                    None
                } else {
                    Some(y_delta / x_delta)
                }
            }
        }

        pub(crate) fn double(self, m: Option<crate::curve_446::Fq2>) -> Self {
            // in the context of elliptic curves, the point at infinity is the zero element of the
            // group
            if self.inner.infinity {
                return self;
            }

            let mut result = self;

            let x = self.inner.x;
            let y = self.inner.y;

            if let Some(m) = m {
                let x3 = m.square() - x.double();
                let y3 = m * (x - x3) - y;

                (result.inner.x, result.inner.y) = (x3, y3);
            } else {
                result.inner.infinity = true;
            }

            result
        }

        pub(crate) fn add_unequal(self, other: G2Affine, m: Option<crate::curve_446::Fq2>) -> Self {
            // in the context of elliptic curves, the point at infinity is the zero element of the
            // group
            if self.inner.infinity {
                return other;
            }
            if other.inner.infinity {
                return self;
            }

            let mut result = self;

            let x1 = self.inner.x;
            let y1 = self.inner.y;
            let x2 = other.inner.x;

            if let Some(m) = m {
                let x3 = m.square() - x1 - x2;
                let y3 = m * (x1 - x3) - y1;

                (result.inner.x, result.inner.y) = (x3, y3);
            } else {
                result.inner.infinity = true;
            }

            result
        }
    }

    #[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Hash, Versionize)]
    #[serde(try_from = "SerializableG2Affine", into = "SerializableG2Affine")]
    #[versionize(try_from = "SerializableG2Affine", into = "SerializableG2Affine")]
    #[repr(transparent)]
    pub struct G2 {
        pub(crate) inner: crate::curve_446::g2::G2Projective,
    }

    impl From<G2> for SerializableG2Affine {
        fn from(value: G2) -> Self {
            SerializableAffine::uncompressed(value.inner.into_affine())
        }
    }

    impl TryFrom<SerializableG2Affine> for G2 {
        type Error = InvalidSerializedAffineError;

        fn try_from(value: SerializableG2Affine) -> Result<Self, Self::Error> {
            Ok(Self {
                inner: Affine::try_from(value)?.into(),
            })
        }
    }

    impl Compressible for G2 {
        type Compressed = SerializableG2Affine;

        type UncompressError = InvalidSerializedAffineError;

        fn compress(&self) -> Self::Compressed {
            SerializableAffine::compressed(self.inner.into_affine())
        }

        fn uncompress(compressed: Self::Compressed) -> Result<Self, Self::UncompressError> {
            compressed.try_into()
        }
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

        // Size in number of bytes when the [to_le_bytes]
        // function is called.
        // This is not the size after serialization!
        pub const BYTE_SIZE: usize = 4 * 7 * 8 + 1;

        pub fn mul_scalar(self, scalar: Zp) -> Self {
            Self {
                inner: mul_zp(self.inner, scalar),
            }
        }

        pub fn mul_scalar_zeroize(self, scalar: &ZeroizeZp) -> Self {
            Self {
                inner: scalar.mul_point(self.inner),
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

        pub fn to_le_bytes(self) -> [u8; Self::BYTE_SIZE] {
            let g = self.inner.into_affine();
            let xc0 = bigint_to_le_bytes(g.x.c0.0 .0);
            let xc1 = bigint_to_le_bytes(g.x.c1.0 .0);
            let yc0 = bigint_to_le_bytes(g.y.c0.0 .0);
            let yc1 = bigint_to_le_bytes(g.y.c1.0 .0);
            let mut buf = [0u8; 4 * 7 * 8 + 1];
            buf[..7 * 8].copy_from_slice(&xc0);
            buf[7 * 8..][..7 * 8].copy_from_slice(&xc1);
            buf[2 * 7 * 8..][..7 * 8].copy_from_slice(&yc0);
            buf[3 * 7 * 8..][..7 * 8].copy_from_slice(&yc1);
            buf[4 * 7 * 8] = g.infinity as u8;
            buf
        }

        pub fn double(self) -> Self {
            let mut this = self;
            this.inner.double_in_place();
            this
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
    use crate::curve_446::{Fq, Fq12, Fq2};
    use crate::serialization::InvalidSerializedAffineError;

    use super::*;
    use ark_ec::pairing::{MillerLoopOutput, Pairing};
    use ark_ff::{CubicExtField, QuadExtField};
    use tfhe_versionable::Versionize;

    type Bls = crate::curve_446::Bls12_446;

    const ZERO: Fq2 = QuadExtField {
        c0: MontFp!("0"),
        c1: MontFp!("0"),
    };

    // computed by copying the result from
    // let two: Fq = MontFp!("2"); println!("{}", two.inverse().unwrap()), which we can't compute in
    // a const context;
    const TWO_INV: Fq = {
        MontFp!("86412351771428577990035638289747981121746346761394949218917418178192828331138736448451251370148591845087981000773214233672031082665302")
    };
    const TWO_INV_MINUS_1: Fq = {
        MontFp!("86412351771428577990035638289747981121746346761394949218917418178192828331138736448451251370148591845087981000773214233672031082665301")
    };

    // the only non zero value in inv(U1) and inv(U3), which come from Olivier's equations.
    const C: Fq2 = QuadExtField {
        c0: TWO_INV,
        c1: TWO_INV_MINUS_1,
    };

    fn fp2_mul_c(x: Fq2) -> Fq2 {
        let x0_c0 = x.c0 * C.c0;
        let x1_c0 = x.c1 * C.c0;

        let x0_c1 = x0_c0 - x.c0;
        let x1_c1 = x1_c0 - x.c1;

        QuadExtField {
            c0: x0_c0 - x1_c1,
            c1: x0_c1 + x1_c0,
        }
    }

    fn fp2_mul_u1_inv(x: Fq2) -> Fq12 {
        QuadExtField {
            c0: CubicExtField {
                c0: ZERO,
                c1: ZERO,
                c2: ZERO,
            },
            c1: CubicExtField {
                c0: ZERO,
                c1: ZERO,
                c2: fp2_mul_c(x),
            },
        }
    }

    fn fp2_mul_u3_inv(x: Fq2) -> Fq12 {
        QuadExtField {
            c0: CubicExtField {
                c0: ZERO,
                c1: ZERO,
                c2: ZERO,
            },
            c1: CubicExtField {
                c0: ZERO,
                c1: fp2_mul_c(x),
                c2: ZERO,
            },
        }
    }

    const fn fp2_to_fp12(x: Fq2) -> Fq12 {
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

    const fn fp_to_fp2(x: Fq) -> Fq2 {
        QuadExtField {
            c0: x,
            c1: MontFp!("0"),
        }
    }

    const fn fp_to_fp12(x: Fq) -> Fq12 {
        fp2_to_fp12(fp_to_fp2(x))
    }

    fn ate_tangent_ev(qt: G2Affine, evpt: G1Affine, m: Fq2) -> Fq12 {
        let qt = qt.inner;
        let evpt = evpt.inner;

        let (xt, yt) = (qt.x, qt.y);
        let (xe, ye) = (evpt.x, evpt.y);

        let l = m;
        let mut l_xe = l;
        l_xe.c0 *= xe;
        l_xe.c1 *= xe;

        let mut r0 = fp_to_fp12(ye);
        let r1 = fp2_mul_u1_inv(l_xe);
        let r2 = fp2_mul_u3_inv(l * xt - yt);

        r0.c1.c1 = r2.c1.c1;
        r0.c1.c2 = -r1.c1.c2;

        r0
    }

    fn ate_line_ev(q1: G2Affine, evpt: G1Affine, m: Fq2) -> Fq12 {
        let q1 = q1.inner;
        let evpt = evpt.inner;

        let (x1, y1) = (q1.x, q1.y);
        let (xe, ye) = (evpt.x, evpt.y);

        let l = m;
        let mut l_xe = l;
        l_xe.c0 *= xe;
        l_xe.c1 *= xe;

        let mut r0 = fp_to_fp12(ye);
        let r1 = fp2_mul_u1_inv(l * fp_to_fp2(xe));
        let r2 = fp2_mul_u3_inv(l * x1 - y1);

        r0.c1.c1 = r2.c1.c1;
        r0.c1.c2 = -r1.c1.c2;

        r0
    }

    #[allow(clippy::needless_range_loop)]
    fn ate_pairing(p: G1, q: G2) -> Gt {
        let t_log2 = 75;
        let t_bits = b"110000000001000001000000100000000000000000000000000000000100000000000000001";

        let mut fk = fp_to_fp12(MontFp!("1"));
        let p = p.normalize();
        let q = q.normalize();

        let mut qk = q;

        for k in 1..t_log2 {
            let m = qk.compute_m(qk).unwrap();
            let lkk = ate_tangent_ev(qk, p, m);
            qk = qk.double(Some(m));
            fk = fk.square() * lkk;

            if t_bits[k] == b'1' {
                let m = q.compute_m(qk);
                let new_qk = q.add_unequal(qk, m);
                if !new_qk.inner.infinity {
                    fk *= ate_line_ev(q, p, m.unwrap());
                }
                qk = new_qk;
            }
        }
        let mlo = MillerLoopOutput(fk);
        Gt {
            inner: Bls::final_exponentiation(mlo).unwrap(),
        }
    }

    #[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Versionize, Hash)]
    #[serde(try_from = "SerializableFp12", into = "SerializableFp12")]
    #[versionize(try_from = "SerializableFp12", into = "SerializableFp12")]
    #[repr(transparent)]
    pub struct Gt {
        pub(crate) inner: ark_ec::pairing::PairingOutput<crate::curve_446::Bls12_446>,
    }

    impl From<Gt> for SerializableFp12 {
        fn from(value: Gt) -> Self {
            value.inner.0.into()
        }
    }

    impl TryFrom<SerializableFp12> for Gt {
        type Error = InvalidSerializedAffineError;

        fn try_from(value: SerializableFp12) -> Result<Self, Self::Error> {
            Ok(Self {
                inner: PairingOutput(value.try_into()?),
            })
        }
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
    use crate::curve_446::FrConfig;
    use crate::serialization::InvalidFpError;
    use ark_ff::{Fp, FpConfig, MontBackend, PrimeField};
    use tfhe_versionable::Versionize;
    use zeroize::{Zeroize, ZeroizeOnDrop};

    fn redc(n: [u64; 5], nprime: u64, t: &mut [u64; 7], out: &mut [u64; 5]) {
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

        out[0] = t[2];
        out[1] = t[3];
        out[2] = t[4];
        out[3] = t[5];
        out[4] = t[6];

        if out.iter().rev().ge(n.iter().rev()) {
            let mut o = false;
            for i in 0..5 {
                let (ti, o0) = u64::overflowing_sub(out[i], n[i]);
                let (ti, o1) = u64::overflowing_sub(ti, o as u64);
                o = o0 | o1;
                out[i] = ti;
            }
        }
        assert!(out.iter().rev().lt(n.iter().rev()));
    }

    #[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Versionize, Hash, Zeroize)]
    #[serde(try_from = "SerializableFp", into = "SerializableFp")]
    #[versionize(try_from = "SerializableFp", into = "SerializableFp")]
    #[repr(transparent)]
    pub struct Zp {
        pub inner: crate::curve_446::Fr,
    }

    impl From<Zp> for SerializableFp {
        fn from(value: Zp) -> Self {
            value.inner.into()
        }
    }
    impl TryFrom<SerializableFp> for Zp {
        type Error = InvalidFpError;

        fn try_from(value: SerializableFp) -> Result<Self, Self::Error> {
            Ok(Self {
                inner: value.try_into()?,
            })
        }
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

        pub fn to_le_bytes(self) -> [u8; 5 * 8] {
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
            let mut res = [0; 5];
            redc(MODULUS.0, MODULUS_MONTGOMERY, &mut n, &mut res);
            Zp {
                inner: Fp(BigInt(res), core::marker::PhantomData),
            }
        }

        pub fn rand(rng: &mut impl rand::RngExt) -> Self {
            Self::from_raw_u64x7([
                rng.random::<u64>(),
                rng.random::<u64>(),
                rng.random::<u64>(),
                rng.random::<u64>(),
                rng.random::<u64>(),
                rng.random::<u64>(),
                rng.random::<u64>(),
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

        pub fn hash_128bit(values: &mut [Zp], data: &[&[u8]]) {
            use sha3::digest::{ExtendableOutput, Update, XofReader};

            let mut hasher = sha3::Shake256::default();
            for data in data {
                hasher.update(data);
            }
            let mut reader = hasher.finalize_xof();

            for value in values {
                let mut bytes = [0u8; 2 * 8];
                reader.read(&mut bytes);
                let limbs: [u64; 2] = unsafe { core::mem::transmute(bytes) };
                *value = Zp {
                    inner: BigInt([limbs[0], limbs[1], 0, 0, 0]).into(),
                };
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

    /// This is like [`Zp`] but will automatically be zeroized on drop, at the cost of not being
    /// Copy
    #[derive(Clone, PartialEq, Eq, Hash, ZeroizeOnDrop)]
    pub struct ZeroizeZp {
        inner: crate::curve_446::Fr,
    }

    #[cfg(test)]
    impl From<ZeroizeZp> for crate::curve_446::Fr {
        fn from(value: ZeroizeZp) -> Self {
            value.inner
        }
    }

    impl Mul<&ZeroizeZp> for &ZeroizeZp {
        type Output = ZeroizeZp;

        #[inline]
        fn mul(self, rhs: &ZeroizeZp) -> Self::Output {
            let mut result = self.clone();
            MontBackend::<FrConfig, 5>::mul_assign(&mut result.inner, &rhs.inner);
            result
        }
    }

    impl Mul<&ZeroizeZp> for Zp {
        type Output = Zp;

        #[inline]
        fn mul(mut self, rhs: &ZeroizeZp) -> Self::Output {
            MontBackend::<FrConfig, 5>::mul_assign(&mut self.inner, &rhs.inner);
            self
        }
    }

    impl Add<&ZeroizeZp> for &ZeroizeZp {
        type Output = ZeroizeZp;

        #[inline]
        fn add(self, rhs: &ZeroizeZp) -> Self::Output {
            let mut result = self.clone();
            MontBackend::<FrConfig, 5>::add_assign(&mut result.inner, &rhs.inner);
            result
        }
    }

    impl Add<&ZeroizeZp> for Zp {
        type Output = Zp;

        #[inline]
        fn add(mut self, rhs: &ZeroizeZp) -> Self::Output {
            MontBackend::<FrConfig, 5>::add_assign(&mut self.inner, &rhs.inner);
            self
        }
    }

    impl ZeroizeZp {
        pub const ZERO: Self = Self {
            inner: MontFp!("0"),
        };

        pub const ONE: Self = Self {
            inner: MontFp!("1"),
        };

        fn reduce_from_raw_u64x7(n: &mut [u64; 7], out: &mut [u64; 5]) {
            const MODULUS: BigInt<5> = BigInt!(
                "645383785691237230677916041525710377746967055506026847120930304831624105190538527824412673"
            );

            const MODULUS_MONTGOMERY: u64 = 272467794636046335;

            // zero the 22 leading bits, so the result is <= MODULUS * 2^128
            n[6] &= (1 << 42) - 1;

            redc(MODULUS.0, MODULUS_MONTGOMERY, n, out);
        }

        /// Replace the content of the provided element with a random but valid one
        pub fn rand_in_place(&mut self, rng: &mut impl rand::RngExt) {
            let mut values = [0; 7];
            rng.fill(&mut values);
            Self::reduce_from_raw_u64x7(&mut values, &mut self.inner.0 .0);
            values.zeroize();
        }

        pub fn mul_point<T: Copy + Zero + Add<Output = T> + Group>(&self, x: T) -> T {
            let zero = T::zero();
            let mut n = self.clone().inner.into_bigint();

            if n.0 == [0; 5] {
                return zero;
            }

            let mut y = zero;
            let mut x = x;

            for word in &n.0 {
                for idx in 0..64 {
                    let bit = (word >> idx) & 1;
                    if bit == 1 {
                        y += x;
                    }
                    x.double_in_place();
                }
            }
            n.zeroize();
            y
        }
    }
}

pub use g1::{G1Affine, G1};
pub use g2::{G2Affine, G2};
pub use gt::Gt;
pub use zp::{ZeroizeZp, Zp};

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{rng, RngExt, SeedableRng};
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
    fn test_compressed_serialization() {
        let rng = &mut StdRng::seed_from_u64(0);
        let alpha = Zp::rand(rng);
        let g_cur = G1::GENERATOR.mul_scalar(alpha);
        let g_hat_cur = G2::GENERATOR.mul_scalar(alpha);

        let g_cur2 = G1::uncompress(
            serde_json::from_str(&serde_json::to_string(&g_cur.compress()).unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(g_cur, g_cur2);

        let g_hat_cur2 = G2::uncompress(
            serde_json::from_str(&serde_json::to_string(&g_hat_cur.compress()).unwrap()).unwrap(),
        )
        .unwrap();
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

    /// Test that ZeroizeZp is equivalent to Zp
    #[test]
    fn test_zeroize_equivalency() {
        let seed = rng().random();
        println!("zeroize_equivalency seed: {seed:x}");
        let rng = &mut StdRng::seed_from_u64(seed);

        let mut zeroize1 = ZeroizeZp::ZERO;
        ZeroizeZp::rand_in_place(&mut zeroize1, rng);
        let mut zeroize2 = ZeroizeZp::ZERO;
        ZeroizeZp::rand_in_place(&mut zeroize2, rng);

        let rng = &mut StdRng::seed_from_u64(seed);
        let zp1 = Zp::rand(rng);
        let zp2 = Zp::rand(rng);

        assert_eq!(zp1.inner, zeroize1.clone().into());
        assert_eq!(zp2.inner, zeroize2.clone().into());

        let sum_zeroize = &zeroize1 + &zeroize2;
        let sum_zp = zp1 + zp2;

        assert_eq!(sum_zp.inner, sum_zeroize.into());

        let sum_zeroize_zp = zp1 + &zeroize2;

        assert_eq!(sum_zp.inner, sum_zeroize_zp.inner);

        let prod_zeroize = &zeroize1 * &zeroize2;
        let prod_zp = zp1 * zp2;

        assert_eq!(prod_zp.inner, prod_zeroize.into());

        let prod_zeroize_zp = zp1 * &zeroize2;

        assert_eq!(prod_zp.inner, prod_zeroize_zp.inner);

        let g1 = G1::GENERATOR;
        let g1_zeroize = g1.mul_scalar_zeroize(&zeroize1);
        let g1_zp = g1.mul_scalar(zp1);

        assert_eq!(g1_zp, g1_zeroize);

        let g2 = G2::GENERATOR;
        let g2_zeroize = g2.mul_scalar_zeroize(&zeroize1);
        let g2_zp = g2.mul_scalar(zp1);

        assert_eq!(g2_zp, g2_zeroize);
    }
}
