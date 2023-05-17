use super::ShortintClientKey;
use super::ShortintServerKey;

use super::IntegerClientKey;
use super::IntegerRadixClientKey;
use super::IntegerServerKey;

use super::HlapiClientKey;
use super::HlapiServerKey;

impl<'a> From<&'a IntegerClientKey> for &'a ShortintClientKey {
    fn from(key: &'a IntegerClientKey) -> &'a ShortintClientKey {
        &key.key
    }
}

impl<'a> From<&'a IntegerRadixClientKey> for &'a ShortintClientKey {
    fn from(key: &'a IntegerRadixClientKey) -> &'a ShortintClientKey {
        From::from(key.as_ref())
    }
}

impl<'a> From<&'a IntegerServerKey> for &'a ShortintServerKey {
    fn from(key: &'a IntegerServerKey) -> &'a ShortintServerKey {
        &key.key
    }
}

impl<'a> From<&'a HlapiClientKey> for &'a ShortintClientKey {
    fn from(key: &'a HlapiClientKey) -> &'a ShortintClientKey {
        match &key.integer_key.key {
            Some(key) => From::from(key),
            None => panic!("CastingKey only constructable if integers are enabled"),
        }
    }
}

impl<'a> From<&'a HlapiServerKey> for &'a ShortintServerKey {
    fn from(key: &'a HlapiServerKey) -> &'a ShortintServerKey {
        match &key.integer_key.key {
            Some(key) => From::from(key),
            None => panic!("CastingKey only constructable if integers are enabled"),
        }
    }
}
