//! Utilities for the library.

/// This macro is used in tandem with the [`zip_args`] macro, to allow to zip iterators and access
/// them in an non-nested fashion. This makes large zip iterators easier to write, but also,
/// makes the code faster, as zipped-flatten iterators are hard to optimize for the compiler.
macro_rules! zip {
    ($($iterator:expr),*)  => {
        $crate::core_crypto::commons::utils::zip!(@zip $($iterator),*)
    };
    (@zip $first:expr, $($iterator:expr),* ) => {
        $first.zip($crate::core_crypto::commons::utils::zip!(@zip $($iterator),*))
    };
    (@zip $first:expr) => {
        $first
    };
}
pub(crate) use zip;

/// Companion macro to flatten the iterators made with the [`zip`]
macro_rules! zip_args {
    ($($iterator:pat),*)  => {
        $crate::core_crypto::commons::utils::zip_args!(@zip $($iterator),*)
    };
    (@zip $first:pat, $second:pat) => {
        ($first, $second)
    };
    (@zip $first:pat, $($iterator:pat),*) => {
        ($first, $crate::core_crypto::commons::utils::zip_args!(@zip $($iterator),*))
    };
}
pub(crate) use zip_args;

#[inline]
fn assert_same_len(a: (usize, Option<usize>), b: (usize, Option<usize>)) {
    debug_assert_eq!(a.1, Some(a.0));
    debug_assert_eq!(b.1, Some(b.0));
    debug_assert_eq!(a.0, b.0);
}

/// Returns a Zip iterator, but checks that the two components have the same length.
pub trait ZipChecked: IntoIterator + Sized {
    #[inline]
    fn zip_checked<B: IntoIterator>(
        self,
        b: B,
    ) -> core::iter::Zip<<Self as IntoIterator>::IntoIter, <B as IntoIterator>::IntoIter> {
        let a = self.into_iter();
        let b = b.into_iter();
        assert_same_len(a.size_hint(), b.size_hint());
        core::iter::zip(a, b)
    }
}

impl<A: IntoIterator> ZipChecked for A {}

// https://docs.rs/itertools/0.7.8/src/itertools/lib.rs.html#247-269
#[allow(unused_macros)]
macro_rules! izip {
    // eg. __izip_closure!(((a, b), c) => (a, b, c) , dd , ee )
    (@ __closure @ $p:pat => $tup:expr) => {
        |$p| $tup
    };

    // The "b" identifier is a different identifier on each recursion level thanks to hygiene.
    (@ __closure @ $p:pat => ( $($tup:tt)* ) , $_iter:expr $( , $tail:expr )*) => {
        $crate::core_crypto::commons::utils::izip!(@ __closure @ ($p, b) => ( $($tup)*, b ) $( , $tail )*)
    };

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
            ::core::iter::IntoIterator::into_iter($first)
                $(.zip_checked($rest))*
                .map($crate::core_crypto::commons::utils::izip!(@ __closure @ a => (a) $( , $rest )*))
        }
    };
}

#[allow(unused_imports)]
pub(crate) use izip;

#[cfg(test)]
mod test {
    #![allow(clippy::many_single_char_names)]

    #[test]
    fn test_zip() {
        let a = vec![1, 2, 3];
        let b = vec![4, 5, 6];
        let c = vec![7, 8, 9];
        let d = vec![10, 11, 12];
        let e = vec![13, 14, 15];
        let f = vec![16, 17, 18];
        let g = vec![19, 20, 21];
        for zip_args!(a, b, c) in zip!(a.iter(), b.iter(), c.iter()) {
            println!("{},{},{}", a, b, c);
        }
        let mut iterator = zip!(
            a.into_iter(),
            b.into_iter(),
            c.into_iter(),
            d.into_iter(),
            e.into_iter(),
            f.into_iter(),
            g.into_iter()
        );
        assert_eq!(
            iterator.next().unwrap(),
            (1, (4, (7, (10, (13, (16, 19))))))
        );
        assert_eq!(
            iterator.next().unwrap(),
            (2, (5, (8, (11, (14, (17, 20))))))
        );
        assert_eq!(
            iterator.next().unwrap(),
            (3, (6, (9, (12, (15, (18, 21))))))
        );
    }
}
