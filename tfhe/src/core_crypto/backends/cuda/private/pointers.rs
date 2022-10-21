use std::ffi::c_void;

#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct StreamPointer(pub *mut c_void);
