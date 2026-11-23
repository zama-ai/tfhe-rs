use std::ops::Deref;

/// 'smart-pointer' that holds either a borrowed T, or an owned T.
///
/// This is essentially like a Cow, except T does not need to be ToOwned
pub enum MaybeCloned<'a, T> {
    Borrowed(&'a T),
    Cloned(T),
}

impl<T> MaybeCloned<'_, T> {
    pub(crate) fn into_owned(self) -> T
    where
        T: ToOwned<Owned = T>,
    {
        match self {
            Self::Borrowed(b) => b.to_owned(),
            Self::Cloned(o) => o,
        }
    }
}

impl<T> Deref for MaybeCloned<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Borrowed(b) => b,
            Self::Cloned(o) => o,
        }
    }
}

/// Inner ciphertext of a high level type, which lives on one device at a time.
///
/// The CPU is the hub. No device converts directly to another one, every transfer
/// goes through the CPU form. A type only describes its own transfers,
/// [move_to_device] owns the policy that is the same for all of them.
pub(in crate::high_level_api) trait DeviceMovable: Sized {
    type CpuCiphertext: Clone;

    fn current_device(&self) -> crate::Device;

    /// Borrows when self already is on the CPU, a copy is only paid for a real transfer
    fn on_cpu(&self) -> MaybeCloned<'_, Self::CpuCiphertext>;

    fn from_cpu(cpu_ct: Self::CpuCiphertext) -> Self;

    /// Also has to handle a ciphertext that sits on another GPU than the one of the streams
    #[cfg(feature = "gpu")]
    fn move_to_gpu(&mut self, streams: &crate::core_crypto::gpu::CudaStreams);

    /// Takes no device so that a type without HPU support can refuse before one is looked up
    #[cfg(feature = "hpu")]
    fn move_to_hpu(&mut self);
}

/// Shared by the boolean, unsigned and signed inner ciphertexts.
#[allow(clippy::needless_pass_by_ref_mut)]
pub(in crate::high_level_api) fn move_to_device<T: DeviceMovable>(
    ct: &mut T,
    target_device: crate::Device,
) {
    match target_device {
        crate::Device::Cpu => {
            if ct.current_device() != crate::Device::Cpu {
                // as_cpu_mut calls itself again after this move, it only terminates if ct
                // really ends up on the CPU
                let cpu_ct = ct.on_cpu().into_owned();
                *ct = T::from_cpu(cpu_ct);
            }
        }
        #[cfg(feature = "gpu")]
        crate::Device::CudaGpu => {
            // No early return when ct already is on a GPU, it may be another one than the key's
            crate::high_level_api::global_state::with_cuda_internal_keys(|key| {
                ct.move_to_gpu(&key.streams);
            });
        }
        #[cfg(feature = "hpu")]
        crate::Device::Hpu => ct.move_to_hpu(),
    }
}
