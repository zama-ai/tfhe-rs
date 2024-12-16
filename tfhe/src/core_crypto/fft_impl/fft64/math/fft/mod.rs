use super::polynomial::{FourierPolynomialMutView, FourierPolynomialView};
use crate::core_crypto::backward_compatibility::fft_impl::{
    FourierPolynomialListVersioned, FourierPolynomialListVersionedOwned,
};
use crate::core_crypto::commons::math::torus::UnsignedTorus;
use crate::core_crypto::commons::numeric::CastInto;
use crate::core_crypto::commons::parameters::{PolynomialCount, PolynomialSize};
use crate::core_crypto::commons::traits::{Container, ContainerMut, IntoContainerOwned};
use crate::core_crypto::commons::utils::izip;
use crate::core_crypto::entities::*;
use aligned_vec::{avec, ABox};
use dyn_stack::{PodStack, SizeOverflow, StackReq};
use rayon::prelude::*;
use std::any::TypeId;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::mem::{align_of, size_of};
use std::sync::{Arc, OnceLock, RwLock};
#[cfg(not(feature = "experimental-force_fft_algo_dif4"))]
use std::time::Duration;
use tfhe_fft::c64;
use tfhe_fft::unordered::{Method, Plan};
use tfhe_versionable::{Unversionize, UnversionizeError, Versionize, VersionizeOwned};

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
mod x86;

/// Twisting factors from the paper:
/// [Fast and Error-Free Negacyclic Integer Convolution using Extended Fourier Transform][paper]
///
/// The real and imaginary parts form (the first `N/2`) `2N`-th roots of unity.
///
/// [paper]: https://eprint.iacr.org/2021/480
#[derive(Clone, Debug, PartialEq)]
pub struct Twisties {
    re: ABox<[f64]>,
    im: ABox<[f64]>,
}

/// View type for [`Twisties`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TwistiesView<'a> {
    re: &'a [f64],
    im: &'a [f64],
}

impl Twisties {
    pub fn as_view(&self) -> TwistiesView<'_> {
        TwistiesView {
            re: &self.re,
            im: &self.im,
        }
    }
}

impl Twisties {
    /// Create a new [`Twisties`] containing the `2N`-th roots of unity with `n = N/2`.
    ///
    /// # Panics
    ///
    /// Panics if `n` is not a power of two.
    pub fn new(n: usize) -> Self {
        debug_assert!(n.is_power_of_two());
        let mut re = avec![0.0; n].into_boxed_slice();
        let mut im = avec![0.0; n].into_boxed_slice();

        let unit = core::f64::consts::PI / (2.0 * n as f64);
        for (i, (re, im)) in izip!(&mut *re, &mut *im).enumerate() {
            (*im, *re) = (i as f64 * unit).sin_cos();
        }

        Self { re, im }
    }
}

/// Negacyclic Fast Fourier Transform. See [`FftView`] for transform functions.
///
/// This structure contains the twisting factors as well as the
/// FFT plan needed for the negacyclic convolution over the reals.
#[derive(Clone, Debug)]
pub struct Fft {
    plan: Arc<(Twisties, Plan)>,
}

/// View type for [`Fft`].
#[derive(Clone, Copy, Debug)]
pub struct FftView<'a> {
    plan: &'a Plan,
    twisties: TwistiesView<'a>,
}

impl Fft {
    #[inline]
    pub fn as_view(&self) -> FftView<'_> {
        FftView {
            plan: &self.plan.1,
            twisties: self.plan.0.as_view(),
        }
    }
}

type PlanMap = RwLock<HashMap<usize, Arc<OnceLock<Arc<(Twisties, Plan)>>>>>;
pub(crate) static PLANS: OnceLock<PlanMap> = OnceLock::new();
fn plans() -> &'static PlanMap {
    PLANS.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Return the input slice, cast to the same type.
///
/// This is useful when the fact that `From` and `To` are the same type cannot be proven in the
/// type system, but is known to be true at runtime.
///
/// # Panics
///
/// Panics if `From` and `To` are not the same type
#[inline]
#[allow(dead_code)]
fn id_mut<From: 'static, To: 'static>(slice: &mut [From]) -> &mut [To] {
    assert_eq!(size_of::<From>(), size_of::<To>());
    assert_eq!(align_of::<From>(), align_of::<To>());
    assert_eq!(TypeId::of::<From>(), TypeId::of::<To>());

    let len = slice.len();
    let ptr = slice.as_mut_ptr();
    unsafe { core::slice::from_raw_parts_mut(ptr.cast::<To>(), len) }
}

/// Return the input slice, cast to the same type.
///
/// This is useful when the fact that `From` and `To` are the same type cannot be proven in the
/// type system, but is known to be true at runtime.
///
/// # Panics
///
/// Panics if `From` and `To` are not the same type
#[inline]
#[allow(dead_code)]
fn id<From: 'static, To: 'static>(slice: &[From]) -> &[To] {
    assert_eq!(size_of::<From>(), size_of::<To>());
    assert_eq!(align_of::<From>(), align_of::<To>());
    assert_eq!(TypeId::of::<From>(), TypeId::of::<To>());

    let len = slice.len();
    let ptr = slice.as_ptr();
    unsafe { core::slice::from_raw_parts(ptr.cast::<To>(), len) }
}

impl Fft {
    /// Real polynomial of size `size`.
    pub fn new(size: PolynomialSize) -> Self {
        let global_plans = plans();

        let n = size.0;
        let get_plan = || {
            let plans = global_plans.read().unwrap();
            let plan = plans.get(&n).cloned();
            drop(plans);

            plan.map(|p| {
                p.get_or_init(|| {
                    #[cfg(not(feature = "experimental-force_fft_algo_dif4"))]
                    {
                        Arc::new((
                            Twisties::new(n / 2),
                            Plan::new(n / 2, Method::Measure(Duration::from_millis(10))),
                        ))
                    }
                    #[cfg(feature = "experimental-force_fft_algo_dif4")]
                    {
                        Arc::new((
                            Twisties::new(n / 2),
                            Plan::new(
                                n / 2,
                                Method::UserProvided {
                                    base_algo: tfhe_fft::ordered::FftAlgo::Dif4,
                                    base_n: n / 2,
                                },
                            ),
                        ))
                    }
                })
                .clone()
            })
        };

        // could not find a plan of the given size, we lock the map again and try to insert it
        let mut plans = global_plans.write().unwrap();
        if let Entry::Vacant(v) = plans.entry(n) {
            v.insert(Arc::new(OnceLock::new()));
        }

        drop(plans);

        Self {
            plan: get_plan().unwrap(),
        }
    }
}

#[cfg_attr(feature = "__profiling", inline(never))]
fn convert_forward_torus<Scalar: UnsignedTorus>(
    out: &mut [c64],
    in_re: &[Scalar],
    in_im: &[Scalar],
    twisties: TwistiesView<'_>,
) {
    let normalization = 2.0_f64.powi(-(Scalar::BITS as i32));

    izip!(out, in_re, in_im, twisties.re, twisties.im).for_each(
        |(out, in_re, in_im, w_re, w_im)| {
            let in_re: f64 = in_re.into_signed().cast_into() * normalization;
            let in_im: f64 = in_im.into_signed().cast_into() * normalization;
            *out = c64 {
                re: in_re,
                im: in_im,
            } * c64 {
                re: *w_re,
                im: *w_im,
            };
        },
    );
}

fn convert_forward_integer_scalar<Scalar: UnsignedTorus>(
    out: &mut [c64],
    in_re: &[Scalar],
    in_im: &[Scalar],
    twisties: TwistiesView<'_>,
) {
    izip!(out, in_re, in_im, twisties.re, twisties.im).for_each(
        |(out, in_re, in_im, w_re, w_im)| {
            let in_re: f64 = in_re.into_signed().cast_into();
            let in_im: f64 = in_im.into_signed().cast_into();
            *out = c64 {
                re: in_re,
                im: in_im,
            } * c64 {
                re: *w_re,
                im: *w_im,
            };
        },
    );
}

#[cfg_attr(feature = "__profiling", inline(never))]
fn convert_forward_integer<Scalar: UnsignedTorus>(
    out: &mut [c64],
    in_re: &[Scalar],
    in_im: &[Scalar],
    twisties: TwistiesView<'_>,
) {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        if Scalar::BITS == 32 {
            x86::convert_forward_integer_u32(out, id(in_re), id(in_im), twisties);
        } else if Scalar::BITS == 64 {
            x86::convert_forward_integer_u64(out, id(in_re), id(in_im), twisties);
        } else {
            unreachable!();
        }
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    convert_forward_integer_scalar::<Scalar>(out, in_re, in_im, twisties);
}

#[cfg_attr(feature = "__profiling", inline(never))]
fn convert_backward_torus<Scalar: UnsignedTorus>(
    out_re: &mut [Scalar],
    out_im: &mut [Scalar],
    inp: &[c64],
    twisties: TwistiesView<'_>,
) {
    let normalization = 1.0 / inp.len() as f64;
    izip!(out_re, out_im, inp, twisties.re, twisties.im).for_each(
        |(out_re, out_im, inp, w_re, w_im)| {
            let tmp = inp
                * (c64 {
                    re: *w_re,
                    im: -*w_im,
                } * normalization);

            *out_re = Scalar::from_torus(tmp.re);
            *out_im = Scalar::from_torus(tmp.im);
        },
    );
}

fn convert_add_backward_torus_scalar<Scalar: UnsignedTorus>(
    out_re: &mut [Scalar],
    out_im: &mut [Scalar],
    inp: &[c64],
    twisties: TwistiesView<'_>,
) {
    let normalization = 1.0 / inp.len() as f64;
    izip!(out_re, out_im, inp, twisties.re, twisties.im).for_each(
        |(out_re, out_im, inp, w_re, w_im)| {
            let tmp = inp
                * (c64 {
                    re: *w_re,
                    im: -*w_im,
                } * normalization);

            *out_re = Scalar::wrapping_add(*out_re, Scalar::from_torus(tmp.re));
            *out_im = Scalar::wrapping_add(*out_im, Scalar::from_torus(tmp.im));
        },
    );
}

#[cfg_attr(feature = "__profiling", inline(never))]
fn convert_add_backward_torus<Scalar: UnsignedTorus>(
    out_re: &mut [Scalar],
    out_im: &mut [Scalar],
    inp: &[c64],
    twisties: TwistiesView<'_>,
) {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        if Scalar::BITS == 32 {
            x86::convert_add_backward_torus_u32(id_mut(out_re), id_mut(out_im), inp, twisties);
        } else if Scalar::BITS == 64 {
            x86::convert_add_backward_torus_u64(id_mut(out_re), id_mut(out_im), inp, twisties);
        } else {
            unreachable!();
        }
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    convert_add_backward_torus_scalar::<Scalar>(out_re, out_im, inp, twisties);
}

impl FftView<'_> {
    /// Return the polynomial size that this FFT was made for.
    pub fn polynomial_size(self) -> PolynomialSize {
        PolynomialSize(2 * self.plan.fft_size())
    }

    /// Serializes data in the Fourier domain.
    pub fn serialize_fourier_buffer<S: serde::Serializer>(
        self,
        serializer: S,
        buf: &[c64],
    ) -> Result<S::Ok, S::Error> {
        self.plan.serialize_fourier_buffer(serializer, buf)
    }

    /// Deserializes data in the Fourier domain
    pub fn deserialize_fourier_buffer<'de, D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
        buf: &mut [c64],
    ) -> Result<(), D::Error> {
        self.plan.deserialize_fourier_buffer(deserializer, buf)
    }

    /// Return the memory required for a forward negacyclic FFT.
    pub fn forward_scratch(self) -> Result<StackReq, SizeOverflow> {
        self.plan.fft_scratch()
    }

    /// Return the memory required for a backward negacyclic FFT.
    pub fn backward_scratch(self) -> Result<StackReq, SizeOverflow> {
        self.plan
            .fft_scratch()?
            .try_and(StackReq::try_new_aligned::<c64>(
                self.polynomial_size().to_fourier_polynomial_size().0,
                aligned_vec::CACHELINE_ALIGN,
            )?)
    }

    /// Perform a negacyclic real FFT of `standard`, viewed as torus elements, and stores the
    /// result in `fourier`.
    ///
    /// # Note
    ///
    /// this function leaves all the elements of `out` in an initialized state.
    ///
    /// # Panics
    ///
    /// Panics if `standard` and `self` have differing polynomial sizes, or if `fourier` doesn't
    /// have size equal to that amount divided by two.
    pub fn forward_as_torus<'out, Scalar: UnsignedTorus>(
        self,
        fourier: FourierPolynomialMutView<'out>,
        standard: PolynomialView<'_, Scalar>,
        stack: &mut PodStack,
    ) -> FourierPolynomialMutView<'out> {
        self.forward_with_conv(fourier, standard, convert_forward_torus, stack)
    }

    /// Perform a negacyclic real FFT of `standard`, viewed as integers, and stores the result in
    /// `fourier`.
    ///
    /// # Note
    ///
    /// this function leaves all the elements of `out` in an initialized state.
    ///
    /// # Panics
    ///
    /// Panics if `standard` and `self` have differing polynomial sizes, or if `fourier` doesn't
    /// have size equal to that amount divided by two.
    pub fn forward_as_integer<'out, Scalar: UnsignedTorus>(
        self,
        fourier: FourierPolynomialMutView<'out>,
        standard: PolynomialView<'_, Scalar>,
        stack: &mut PodStack,
    ) -> FourierPolynomialMutView<'out> {
        self.forward_with_conv(fourier, standard, convert_forward_integer, stack)
    }

    #[must_use]
    pub fn incomplete_monomial_forward_as_integer(
        self,
        fourier: FourierPolynomialMutView<'_>,
        degree: usize,
    ) -> c64 {
        let n = self.polynomial_size().0;
        let fourier = fourier.data;

        let negate = (degree / n) % 2 == 1;
        let degree = degree % n;

        assert!(degree < n);

        let unit = if degree >= n / 2 {
            c64::new(0.0, 1.0) // imaginary unit
        } else {
            c64::new(1.0, 0.0) // real unit
        };
        let folded_degree = if degree >= n / 2 {
            degree - n / 2
        } else {
            degree
        };

        self.plan.fwd_monomial(folded_degree, fourier);

        let twist = unit
            * c64::new(
                self.twisties.re[folded_degree],
                self.twisties.im[folded_degree],
            );

        if negate {
            -twist
        } else {
            twist
        }
    }

    /// Perform an inverse negacyclic real FFT of `fourier` and stores the result in `standard`,
    /// viewed as torus elements.
    ///
    /// # Note
    ///
    /// this function leaves all the elements of `out_re` and `out_im` in an initialized state.
    ///
    /// # Panics
    ///
    /// See [`Self::forward_as_torus`]
    pub fn backward_as_torus<Scalar: UnsignedTorus>(
        self,
        standard: PolynomialMutView<'_, Scalar>,
        fourier: FourierPolynomialView<'_>,
        stack: &mut PodStack,
    ) {
        self.backward_with_conv(standard, fourier, convert_backward_torus, stack);
    }

    /// Perform an inverse negacyclic real FFT of `fourier` and adds the result to `standard`,
    /// viewed as torus elements.
    ///
    /// # Note
    ///
    /// this function leaves all the elements of `out_re` and `out_im` in an initialized state.
    ///
    /// # Panics
    ///
    /// See [`Self::forward_as_torus`]
    pub fn add_backward_as_torus<Scalar: UnsignedTorus>(
        self,
        standard: PolynomialMutView<'_, Scalar>,
        fourier: FourierPolynomialView<'_>,
        stack: &mut PodStack,
    ) {
        self.backward_with_conv(standard, fourier, convert_add_backward_torus, stack);
    }

    /// Variant of [`Self::add_backward_as_torus`] writing the output of the backward fourier
    /// transform in the [`FourierPolynomialMutView`] in place.
    pub fn add_backward_in_place_as_torus<Scalar: UnsignedTorus>(
        self,
        standard: PolynomialMutView<'_, Scalar>,
        fourier: FourierPolynomialMutView<'_>,
        stack: &mut PodStack,
    ) {
        self.backward_with_conv_in_place(standard, fourier, convert_add_backward_torus, stack);
    }

    fn forward_with_conv<
        'out,
        Scalar: UnsignedTorus,
        F: Fn(&mut [c64], &[Scalar], &[Scalar], TwistiesView<'_>),
    >(
        self,
        fourier: FourierPolynomialMutView<'out>,
        standard: PolynomialView<'_, Scalar>,
        conv_fn: F,
        stack: &mut PodStack,
    ) -> FourierPolynomialMutView<'out> {
        let fourier = fourier.data;
        let standard = standard.as_ref();
        let n = standard.len();
        debug_assert_eq!(n, 2 * fourier.len());
        let (standard_re, standard_im) = standard.split_at(n / 2);
        conv_fn(fourier, standard_re, standard_im, self.twisties);
        self.plan.fwd(fourier, stack);
        FourierPolynomialMutView { data: fourier }
    }

    fn backward_with_conv<
        Scalar: UnsignedTorus,
        F: Fn(&mut [Scalar], &mut [Scalar], &[c64], TwistiesView<'_>),
    >(
        self,
        mut standard: PolynomialMutView<'_, Scalar>,
        fourier: FourierPolynomialView<'_>,
        conv_fn: F,
        stack: &mut PodStack,
    ) {
        let fourier = fourier.data;
        let standard = standard.as_mut();
        let n = standard.len();
        debug_assert_eq!(n, 2 * fourier.len());
        let (tmp, stack) =
            stack.collect_aligned(aligned_vec::CACHELINE_ALIGN, fourier.iter().copied());
        self.plan.inv(tmp, stack);

        let (standard_re, standard_im) = standard.split_at_mut(n / 2);
        conv_fn(standard_re, standard_im, tmp, self.twisties);
    }

    fn backward_with_conv_in_place<
        Scalar: UnsignedTorus,
        F: Fn(&mut [Scalar], &mut [Scalar], &[c64], TwistiesView<'_>),
    >(
        self,
        mut standard: PolynomialMutView<'_, Scalar>,
        fourier: FourierPolynomialMutView<'_>,
        conv_fn: F,
        stack: &mut PodStack,
    ) {
        let fourier = fourier.data;
        let standard = standard.as_mut();
        let n = standard.len();
        debug_assert_eq!(n, 2 * fourier.len());
        self.plan.inv(fourier, stack);

        let (standard_re, standard_im) = standard.split_at_mut(n / 2);
        conv_fn(standard_re, standard_im, fourier, self.twisties);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FourierPolynomialList<C: Container<Element = c64>> {
    pub data: C,
    pub polynomial_size: PolynomialSize,
}

impl<C: Container<Element = c64>> FourierPolynomialList<C> {
    pub fn polynomial_count(&self) -> PolynomialCount {
        PolynomialCount(
            self.data.container_len() / self.polynomial_size.to_fourier_polynomial_size().0,
        )
    }
}

impl<C: ContainerMut<Element = c64>> FourierPolynomialList<C> {
    pub fn iter_mut(
        &mut self,
    ) -> impl DoubleEndedIterator<Item = FourierPolynomial<&'_ mut [c64]>> {
        assert!(
            self.data.container_len() % self.polynomial_size.to_fourier_polynomial_size().0 == 0
        );
        self.data
            .as_mut()
            .chunks_exact_mut(self.polynomial_size.to_fourier_polynomial_size().0)
            .map(move |slice| FourierPolynomial { data: slice })
    }
}

impl<C: Container<Element = c64>> Versionize for FourierPolynomialList<C> {
    type Versioned<'vers>
        = FourierPolynomialListVersioned<'vers>
    where
        C: 'vers;

    fn versionize(&self) -> Self::Versioned<'_> {
        self.into()
    }
}

impl<C: Container<Element = c64>> VersionizeOwned for FourierPolynomialList<C> {
    type VersionedOwned = FourierPolynomialListVersionedOwned;

    fn versionize_owned(self) -> Self::VersionedOwned {
        self.into()
    }
}

impl<C: IntoContainerOwned<Element = c64>> Unversionize for FourierPolynomialList<C> {
    fn unversionize(versioned: Self::VersionedOwned) -> Result<Self, UnversionizeError> {
        Ok(versioned.into())
    }
}

impl<C: Container<Element = c64>> serde::Serialize for FourierPolynomialList<C> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        fn serialize_impl<S: serde::Serializer>(
            data: &[c64],
            polynomial_size: PolynomialSize,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            use crate::core_crypto::commons::traits::Split;

            pub struct SingleFourierPolynomial<'a> {
                fft: FftView<'a>,
                buf: &'a [c64],
            }

            #[cfg_attr(dylint_lib = "tfhe_lints", allow(serialize_without_versionize))]
            impl serde::Serialize for SingleFourierPolynomial<'_> {
                fn serialize<S: serde::Serializer>(
                    &self,
                    serializer: S,
                ) -> Result<S::Ok, S::Error> {
                    self.fft.serialize_fourier_buffer(serializer, self.buf)
                }
            }

            use serde::ser::SerializeSeq;
            let chunk_count = if polynomial_size.0 == 0 {
                0
            } else {
                data.len() / (polynomial_size.to_fourier_polynomial_size().0)
            };

            let mut state = serializer.serialize_seq(Some(2 + chunk_count))?;
            state.serialize_element(&polynomial_size)?;
            state.serialize_element(&chunk_count)?;
            if chunk_count != 0 {
                let fft = Fft::new(polynomial_size);
                for buf in data.split_into(chunk_count) {
                    state.serialize_element(&SingleFourierPolynomial {
                        fft: fft.as_view(),
                        buf,
                    })?;
                }
            }
            state.end()
        }

        serialize_impl(self.data.as_ref(), self.polynomial_size, serializer)
    }
}

impl<'de, C: IntoContainerOwned<Element = c64>> serde::Deserialize<'de>
    for FourierPolynomialList<C>
{
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use std::marker::PhantomData;
        struct SeqVisitor<C: IntoContainerOwned<Element = c64>>(PhantomData<fn() -> C>);

        impl<'de, C: IntoContainerOwned<Element = c64>> serde::de::Visitor<'de> for SeqVisitor<C> {
            type Value = FourierPolynomialList<C>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str(
                    "a sequence of two fields followed by polynomials in the Fourier domain",
                )
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                use crate::core_crypto::commons::traits::Split;

                let str = "sequence of two fields and Fourier polynomials";

                let Some(polynomial_size) = seq.next_element::<PolynomialSize>()? else {
                    return Err(serde::de::Error::invalid_length(0, &str));
                };

                let Some(chunk_count) = seq.next_element::<usize>()? else {
                    return Err(serde::de::Error::invalid_length(1, &str));
                };

                struct FillFourier<'a> {
                    fft: FftView<'a>,
                    buf: &'a mut [c64],
                }

                impl<'de> serde::de::DeserializeSeed<'de> for FillFourier<'_> {
                    type Value = ();

                    fn deserialize<D: serde::Deserializer<'de>>(
                        self,
                        deserializer: D,
                    ) -> Result<Self::Value, D::Error> {
                        self.fft.deserialize_fourier_buffer(deserializer, self.buf)
                    }
                }

                let mut data = C::collect(
                    (0..(polynomial_size.to_fourier_polynomial_size().0 * chunk_count))
                        .map(|_| c64::default()),
                );

                if chunk_count != 0 {
                    let fft = Fft::new(polynomial_size);
                    for (i, buf) in data.as_mut().split_into(chunk_count).enumerate() {
                        match seq.next_element_seed(FillFourier {
                            fft: fft.as_view(),
                            buf,
                        })? {
                            Some(()) => (),
                            None => {
                                return Err(serde::de::Error::invalid_length(
                                    i,
                                    &&*format!("sequence of {chunk_count} Fourier polynomials"),
                                ))
                            }
                        };
                    }
                }

                Ok(FourierPolynomialList {
                    data,
                    polynomial_size,
                })
            }
        }

        deserializer.deserialize_seq(SeqVisitor::<C>(PhantomData))
    }
}

pub fn par_convert_polynomials_list_to_fourier<Scalar: UnsignedTorus>(
    dest: &mut [c64],
    origin: &[Scalar],
    polynomial_size: PolynomialSize,
    fft: FftView<'_>,
) {
    assert_eq!(origin.len() % polynomial_size.0, 0);
    let nb_polynomial = origin.len() / polynomial_size.0;

    let f_polynomial_size = polynomial_size.to_fourier_polynomial_size().0;

    assert_eq!(nb_polynomial * f_polynomial_size, dest.len());

    let nb_threads = rayon::current_num_threads();

    let chunk_size = nb_polynomial.div_ceil(nb_threads);

    dest.par_chunks_mut(chunk_size * f_polynomial_size)
        .zip_eq(origin.par_chunks(chunk_size * polynomial_size.0))
        .for_each(|(fourier_poly_chunk, standard_poly_chunk)| {
            let stack_len = fft
                .forward_scratch()
                .unwrap()
                .try_unaligned_bytes_required()
                .unwrap();
            let mut mem = vec![0; stack_len];

            let stack = PodStack::new(&mut mem);

            for (fourier_poly, standard_poly) in izip!(
                fourier_poly_chunk.chunks_exact_mut(f_polynomial_size),
                standard_poly_chunk.chunks_exact(polynomial_size.0)
            ) {
                fft.forward_as_torus(
                    FourierPolynomialMutView { data: fourier_poly },
                    PolynomialView::from_container(standard_poly),
                    stack,
                );
            }
        });
}

#[cfg(test)]
mod tests;
