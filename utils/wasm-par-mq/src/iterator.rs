use crate::pool::execute_par_map;
#[cfg(feature = "sync-api")]
use crate::pool::execute_par_map_sync;
use crate::registry::{FnEntry, RegisteredFn};
use serde::Serialize;
use serde::de::DeserializeOwned;

pub trait ParallelIterator {
    type Item;

    fn map<F, R>(self, f: FnEntry<F>) -> ParMap<F, Self, R>
    where
        F: RegisteredFn<Input = Self::Item, Output = R>,
        Self: Sized;
}

/// A parallel iterator that distributes work across web workers.
pub struct Iter<'data, T> {
    slice: &'data [T],
}

impl<'data, T> Iter<'data, T> {
    /// Create a new parallel iterator from a slice
    pub(crate) fn new(slice: &'data [T]) -> Self {
        Self { slice }
    }

    /// Get the number of elements
    pub fn len(&self) -> usize {
        self.slice.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.slice.is_empty()
    }
}

impl<'data, T> ParallelIterator for Iter<'data, T> {
    type Item = T;

    /// Apply a registered function to each element in parallel.
    ///
    /// The function must be registered with `register_fn!` before use.
    /// This method is lazy - it returns a `ParMap` that must be collected.
    ///
    /// # Example
    /// ```ignore
    /// fn double(x: i32) -> i32 { x * 2 }
    /// register_fn!(double);
    ///
    /// let results = vec![1, 2, 3, 4]
    ///     .into_par_iter()
    ///     .par_map(double)
    ///     .collect_vec()
    ///     .await;
    /// ```
    fn map<F, R>(self, f: FnEntry<F>) -> ParMap<F, Self, R> {
        ParMap {
            base: self,
            f,
            _marker: std::marker::PhantomData,
        }
    }
}

pub struct IntoIter<T> {
    data: Vec<T>,
}

impl<T> IntoIter<T> {
    /// Create a new parallel iterator from a vector
    pub(crate) fn new(data: Vec<T>) -> Self {
        Self { data }
    }

    /// Get the number of elements
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl<T> ParallelIterator for IntoIter<T> {
    type Item = T;

    fn map<F, R>(self, f: FnEntry<F>) -> ParMap<F, Self, R> {
        ParMap {
            base: self,
            f,
            _marker: std::marker::PhantomData,
        }
    }
}

/// A parallel map operation (lazy - doesn't execute until collected)
pub struct ParMap<F, I, R> {
    base: I,
    f: FnEntry<F>,
    _marker: std::marker::PhantomData<R>,
}

impl<F, I, O> ParMap<F, Iter<'_, I>, O>
where
    I: Serialize,
    O: DeserializeOwned,
    F: RegisteredFn<Input = I, Output = O>,
{
    /// Collect the results of the parallel map operation.
    ///
    /// This is an **async** operation that dispatches work to workers
    /// and waits for all results.
    ///
    /// # Panics
    /// Panics if the worker pool has not been initialized.
    pub async fn collect_vec(self) -> Vec<O> {
        self.try_collect_vec().await.expect("parallel map failed")
    }

    /// Collect results, returning an error on failure instead of panicking
    pub async fn try_collect_vec(self) -> Result<Vec<O>, String> {
        execute_par_map(self.f, self.base.slice).await
    }
    /// Collect the results of the parallel map operation.
    ///
    /// This is a **sync** operation that dispatches work to workers
    /// and blocks until they all return.
    ///
    /// # Panics
    /// Panics if the worker pool has not been initialized.
    #[cfg(feature = "sync-api")]
    pub fn collect_vec_sync(self) -> Vec<O> {
        self.try_collect_vec_sync().expect("parallel map failed")
    }

    /// Collect results, returning an error on failure instead of panicking
    #[cfg(feature = "sync-api")]
    pub fn try_collect_vec_sync(self) -> Result<Vec<O>, String> {
        execute_par_map_sync(self.f, self.base.slice)
    }
}

impl<F, I, O> ParMap<F, IntoIter<I>, O>
where
    I: Serialize,
    O: DeserializeOwned,
    F: RegisteredFn<Input = I, Output = O>,
{
    /// Collect the results of the parallel map operation.
    ///
    /// This is an **async** operation that dispatches work to workers
    /// and waits for all results.
    ///
    /// # Panics
    /// Panics if the worker pool has not been initialized.
    pub async fn collect_vec(self) -> Vec<O> {
        self.try_collect_vec().await.expect("parallel map failed")
    }

    /// Collect results, returning an error on failure instead of panicking
    pub async fn try_collect_vec(self) -> Result<Vec<O>, String> {
        execute_par_map(self.f, &self.base.data).await
    }

    /// Collect the results of the parallel map operation.
    ///
    /// This is a **sync** operation that dispatches work to workers
    /// and blocks until they all return.
    ///
    /// # Panics
    /// Panics if the worker pool has not been initialized.
    #[cfg(feature = "sync-api")]
    pub fn collect_vec_sync(self) -> Vec<O> {
        self.try_collect_vec_sync().expect("parallel map failed")
    }

    /// Collect results, returning an error on failure instead of panicking
    #[cfg(feature = "sync-api")]
    pub fn try_collect_vec_sync(self) -> Result<Vec<O>, String> {
        execute_par_map_sync(self.f, &self.base.data)
    }
}

/// Extension trait to convert collections into parallel iterators
pub trait IntoParallelIterator {
    type Item;
    type Iter: ParallelIterator<Item = Self::Item>;

    /// Convert this collection into a parallel iterator
    fn into_par_iter(self) -> Self::Iter;
}

impl<T> IntoParallelIterator for Vec<T> {
    type Item = T;
    type Iter = IntoIter<T>;

    fn into_par_iter(self) -> Self::Iter {
        IntoIter::new(self)
    }
}

impl<'data, T: Serialize> IntoParallelIterator for &'data [T] {
    type Item = T;
    type Iter = Iter<'data, T>;

    fn into_par_iter(self) -> Self::Iter {
        Iter::new(self)
    }
}

/// Extension trait that mirrors rayon's par_iter() method on slices
pub trait ParallelSlice<T> {
    fn par_iter(&'_ self) -> Iter<'_, T>;
}

impl<T> ParallelSlice<T> for [T] {
    fn par_iter(&'_ self) -> Iter<'_, T> {
        Iter::new(self)
    }
}

impl<T> ParallelSlice<T> for Vec<T> {
    fn par_iter(&'_ self) -> Iter<'_, T> {
        Iter::new(self)
    }
}
