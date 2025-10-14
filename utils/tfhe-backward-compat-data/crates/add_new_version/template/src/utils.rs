use std::path::Path;

use tfhe_versionable::Versionize;

use tfhe_backward_compat_data::generate::*;
use tfhe_backward_compat_data::*;

pub(crate) fn store_versioned_test<Data: Versionize + 'static, P: AsRef<Path>>(
    msg: &Data,
    dir: P,
    test_filename: &str,
) {
    generic_store_versioned_test(Versionize::versionize, msg, dir, test_filename)
}

#[allow(dead_code)]
pub(crate) fn store_versioned_auxiliary<Data: Versionize + 'static, P: AsRef<Path>>(
    msg: &Data,
    dir: P,
    test_filename: &str,
) {
    generic_store_versioned_auxiliary(Versionize::versionize, msg, dir, test_filename)
}

/// This trait allows to convert version independent parameters types defined in
/// `tfhe-backward-compat-data` to the equivalent TFHE-rs parameters for this version.
///
/// This is similar to `Into` but allows to circumvent the orphan rule.
pub(crate) trait ConvertParams<TfheRsParams> {
    fn convert(self) -> TfheRsParams;
}

// <TODO> Add here the impl of ConvertParams for the TestXXXParameterSet that you need.
// <TODO> You can start by simply copying the implementations of this trait from the crate for
// <TODO> the previous version, and then eventually fix parameter types that have been updated.
