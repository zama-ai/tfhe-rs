//! Utilities for the library.

/// Return a Zip iterator, but checks that the two components have the same length.
pub trait ZipChecked: IntoIterator + Sized
where
    <Self as IntoIterator>::IntoIter: ExactSizeIterator,
{
    #[track_caller]
    #[inline]
    fn zip_checked<B: IntoIterator>(
        self,
        b: B,
    ) -> core::iter::Zip<<Self as IntoIterator>::IntoIter, <B as IntoIterator>::IntoIter>
    where
        <B as IntoIterator>::IntoIter: ExactSizeIterator,
    {
        let a = self.into_iter();
        let b = b.into_iter();
        assert_eq!(a.len(), b.len());
        core::iter::zip(a, b)
    }
}

impl<A: IntoIterator> ZipChecked for A where <A as IntoIterator>::IntoIter: ExactSizeIterator {}

// https://docs.rs/itertools/0.7.8/src/itertools/lib.rs.html#247-269
macro_rules! izip_eq {
    (@ __closure @ ($a:expr)) => { |a| (a,) };
    (@ __closure @ ($a:expr, $b:expr)) => { |(a, b)| (a, b) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr)) => { |((a, b), c)| (a, b, c) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr)) => { |(((a, b), c), d)| (a, b, c, d) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr)) => { |((((a, b), c), d), e)| (a, b, c, d, e) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr)) => { |(((((a, b), c), d), e), f)| (a, b, c, d, e, f) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr, $g:expr)) => { |((((((a, b), c), d), e), f), g)| (a, b, c, d, e, f, g) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr, $g:expr, $h:expr)) => { |(((((((a, b), c), d), e), f), g), h)| (a, b, c, d, e, f, g, h) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr, $g:expr, $h:expr, $i: expr)) => { |((((((((a, b), c), d), e), f), g), h), i)| (a, b, c, d, e, f, g, h, i) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr, $g:expr, $h:expr, $i: expr, $j: expr)) => { |(((((((((a, b), c), d), e), f), g), h), i), j)| (a, b, c, d, e, f, g, h, i, j) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr, $g:expr, $h:expr, $i: expr, $j: expr, $k: expr)) => { |((((((((((a, b), c), d), e), f), g), h), i), j), k)| (a, b, c, d, e, f, g, h, i, j, k) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr, $g:expr, $h:expr, $i: expr, $j: expr, $k: expr, $l: expr)) => { |(((((((((((a, b), c), d), e), f), g), h), i), j), k), l)| (a, b, c, d, e, f, g, h, i, j, k, l) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr, $g:expr, $h:expr, $i: expr, $j: expr, $k: expr, $l: expr, $m:expr)) => { |((((((((((((a, b), c), d), e), f), g), h), i), j), k), l), m)| (a, b, c, d, e, f, g, h, i, j, k, l, m) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr, $g:expr, $h:expr, $i: expr, $j: expr, $k: expr, $l: expr, $m:expr, $n:expr)) => { |(((((((((((((a, b), c), d), e), f), g), h), i), j), k), l), m), n)| (a, b, c, d, e, f, g, h, i, j, k, l, m, n) };
    (@ __closure @ ($a:expr, $b:expr, $c:expr, $d:expr, $e: expr, $f:expr, $g:expr, $h:expr, $i: expr, $j: expr, $k: expr, $l: expr, $m:expr, $n:expr, $o:expr)) => { |((((((((((((((a, b), c), d), e), f), g), h), i), j), k), l), m), n), o)| (a, b, c, d, e, f, g, h, i, j, k, l, m, n, o) };

    ( $first:expr $(,)?) => {
        {
            #[allow(unused_imports)]
            use $crate::core_crypto::commons::utils::ZipChecked;
            ::core::iter::IntoIterator::into_iter($first)
        }
    };
    ( $first:expr, $($rest:expr),+ $(,)?) => {
        {
            #[allow(unused_imports)]
            use $crate::core_crypto::commons::utils::ZipChecked;
            $first
                $(.zip_checked($rest))*
                .map($crate::core_crypto::commons::utils::izip_eq!(@ __closure @ ($first, $($rest),*)))
        }
    };
}

pub(crate) use izip_eq;
