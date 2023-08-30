use std::cell::RefCell;
use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

#[cfg(feature = "internal-keycache")]
use crate::shortint::keycache::KEY_CACHE;
use crate::shortint::{CompressedServerKey, ServerKey};

use super::client_key::GenericShortIntClientKey;
use super::parameters::ShortIntegerParameter;
use super::types::GenericShortInt;

/// The internal key of a short integer type
///
/// A wrapper around `tfhe-shortint` `ServerKey`
#[derive(Clone, Serialize, Deserialize)]
pub struct GenericShortIntServerKey<P: ShortIntegerParameter> {
    pub(super) key: ServerKey,
    _marker: PhantomData<P>,
}

/// The internal key wraps some of the inner ServerKey methods
/// so that its input and outputs are type of this crate.
impl<P> GenericShortIntServerKey<P>
where
    P: ShortIntegerParameter,
{
    pub(crate) fn new(client_key: &GenericShortIntClientKey<P>) -> Self {
        #[cfg(feature = "internal-keycache")]
        let key = {
            let pbs_param = client_key.key.parameters.pbs_parameters().unwrap();
            KEY_CACHE.get_from_param(pbs_param).server_key().clone()
        };
        #[cfg(not(feature = "internal-keycache"))]
        let key = ServerKey::new(&client_key.key);

        Self {
            key,
            _marker: Default::default(),
        }
    }

    pub(crate) fn add(
        &self,
        lhs: &GenericShortInt<P>,
        rhs: &GenericShortInt<P>,
    ) -> GenericShortInt<P> {
        let ciphertext = self
            .key
            .add(&lhs.ciphertext.borrow(), &rhs.ciphertext.borrow());
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn sub(
        &self,
        lhs: &GenericShortInt<P>,
        rhs: &GenericShortInt<P>,
    ) -> GenericShortInt<P> {
        let ciphertext = self
            .key
            .sub(&lhs.ciphertext.borrow(), &rhs.ciphertext.borrow());
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn mul(
        &self,
        lhs: &GenericShortInt<P>,
        rhs: &GenericShortInt<P>,
    ) -> GenericShortInt<P> {
        let ciphertext = self
            .key
            .mul_lsb(&lhs.ciphertext.borrow(), &rhs.ciphertext.borrow());
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn div(
        &self,
        lhs: &GenericShortInt<P>,
        rhs: &GenericShortInt<P>,
    ) -> GenericShortInt<P> {
        let ciphertext = self
            .key
            .div(&lhs.ciphertext.borrow(), &rhs.ciphertext.borrow());
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn add_assign(&self, lhs: &GenericShortInt<P>, rhs: &GenericShortInt<P>) {
        self.key
            .add_assign(&mut lhs.ciphertext.borrow_mut(), &rhs.ciphertext.borrow());
    }

    pub(crate) fn sub_assign(&self, lhs: &GenericShortInt<P>, rhs: &GenericShortInt<P>) {
        self.key
            .sub_assign(&mut lhs.ciphertext.borrow_mut(), &rhs.ciphertext.borrow());
    }

    pub(crate) fn mul_assign(&self, lhs: &GenericShortInt<P>, rhs: &GenericShortInt<P>) {
        self.key
            .mul_lsb_assign(&mut lhs.ciphertext.borrow_mut(), &rhs.ciphertext.borrow());
    }

    pub(crate) fn div_assign(&self, lhs: &GenericShortInt<P>, rhs: &GenericShortInt<P>) {
        self.key
            .div_assign(&mut lhs.ciphertext.borrow_mut(), &rhs.ciphertext.borrow())
    }

    pub(crate) fn bitand_assign(&self, lhs: &GenericShortInt<P>, rhs: &GenericShortInt<P>) {
        self.key
            .bitand_assign(&mut lhs.ciphertext.borrow_mut(), &rhs.ciphertext.borrow());
    }

    pub(crate) fn bitor_assign(&self, lhs: &GenericShortInt<P>, rhs: &GenericShortInt<P>) {
        self.key
            .bitor_assign(&mut lhs.ciphertext.borrow_mut(), &rhs.ciphertext.borrow());
    }

    pub(crate) fn bitxor_assign(&self, lhs: &GenericShortInt<P>, rhs: &GenericShortInt<P>) {
        self.key
            .bitxor_assign(&mut lhs.ciphertext.borrow_mut(), &rhs.ciphertext.borrow());
    }

    pub(crate) fn scalar_sub(&self, lhs: &GenericShortInt<P>, rhs: u8) -> GenericShortInt<P> {
        let ciphertext = self.key.scalar_sub(&lhs.ciphertext.borrow(), rhs);
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn scalar_mul(&self, lhs: &GenericShortInt<P>, rhs: u8) -> GenericShortInt<P> {
        let ciphertext = self.key.scalar_mul(&lhs.ciphertext.borrow(), rhs);
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn scalar_add(&self, lhs: &GenericShortInt<P>, scalar: u8) -> GenericShortInt<P> {
        let ciphertext = self.key.scalar_add(&lhs.ciphertext.borrow(), scalar);
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn scalar_add_assign(&self, lhs: &GenericShortInt<P>, rhs: u8) {
        self.key
            .scalar_add_assign(&mut lhs.ciphertext.borrow_mut(), rhs)
    }

    pub(crate) fn scalar_mul_assign(&self, lhs: &GenericShortInt<P>, rhs: u8) {
        self.key
            .scalar_mul_assign(&mut lhs.ciphertext.borrow_mut(), rhs)
    }

    pub(crate) fn scalar_sub_assign(&self, lhs: &GenericShortInt<P>, rhs: u8) {
        self.key
            .scalar_sub_assign(&mut lhs.ciphertext.borrow_mut(), rhs)
    }

    pub(crate) fn bitand(
        &self,
        lhs: &GenericShortInt<P>,
        rhs: &GenericShortInt<P>,
    ) -> GenericShortInt<P> {
        let ciphertext = self
            .key
            .bitand(&lhs.ciphertext.borrow(), &rhs.ciphertext.borrow());
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn bitor(
        &self,
        lhs: &GenericShortInt<P>,
        rhs: &GenericShortInt<P>,
    ) -> GenericShortInt<P> {
        let ciphertext = self
            .key
            .bitor(&lhs.ciphertext.borrow(), &rhs.ciphertext.borrow());
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn bitxor(
        &self,
        lhs: &GenericShortInt<P>,
        rhs: &GenericShortInt<P>,
    ) -> GenericShortInt<P> {
        let ciphertext = self
            .key
            .bitxor(&lhs.ciphertext.borrow(), &rhs.ciphertext.borrow());
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn less(
        &self,
        lhs: &GenericShortInt<P>,
        rhs: &GenericShortInt<P>,
    ) -> GenericShortInt<P> {
        let ciphertext = self
            .key
            .less(&lhs.ciphertext.borrow(), &rhs.ciphertext.borrow());
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn less_or_equal(
        &self,
        lhs: &GenericShortInt<P>,
        rhs: &GenericShortInt<P>,
    ) -> GenericShortInt<P> {
        let ciphertext = self
            .key
            .less_or_equal(&lhs.ciphertext.borrow(), &rhs.ciphertext.borrow());
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn greater(
        &self,
        lhs: &GenericShortInt<P>,
        rhs: &GenericShortInt<P>,
    ) -> GenericShortInt<P> {
        let ciphertext = self
            .key
            .greater(&lhs.ciphertext.borrow(), &rhs.ciphertext.borrow());
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn greater_or_equal(
        &self,
        lhs: &GenericShortInt<P>,
        rhs: &GenericShortInt<P>,
    ) -> GenericShortInt<P> {
        let ciphertext = self
            .key
            .greater_or_equal(&lhs.ciphertext.borrow(), &rhs.ciphertext.borrow());
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn equal(
        &self,
        lhs: &GenericShortInt<P>,
        rhs: &GenericShortInt<P>,
    ) -> GenericShortInt<P> {
        let ciphertext = self
            .key
            .equal(&lhs.ciphertext.borrow(), &rhs.ciphertext.borrow());
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn not_equal(
        &self,
        lhs: &GenericShortInt<P>,
        rhs: &GenericShortInt<P>,
    ) -> GenericShortInt<P> {
        let ciphertext = self
            .key
            .not_equal(&lhs.ciphertext.borrow(), &rhs.ciphertext.borrow());
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn scalar_equal(&self, lhs: &GenericShortInt<P>, scalar: u8) -> GenericShortInt<P> {
        let ciphertext = self
            .key
            .scalar_equal(&mut lhs.ciphertext.borrow_mut(), scalar);
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn scalar_not_equal(
        &self,
        lhs: &GenericShortInt<P>,
        scalar: u8,
    ) -> GenericShortInt<P> {
        let ciphertext = self
            .key
            .scalar_not_equal(&mut lhs.ciphertext.borrow_mut(), scalar);
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn scalar_greater_or_equal(
        &self,
        lhs: &GenericShortInt<P>,
        scalar: u8,
    ) -> GenericShortInt<P> {
        let ciphertext = self
            .key
            .scalar_greater_or_equal(&mut lhs.ciphertext.borrow_mut(), scalar);
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn scalar_less_or_equal(
        &self,
        lhs: &GenericShortInt<P>,
        scalar: u8,
    ) -> GenericShortInt<P> {
        let ciphertext = self
            .key
            .scalar_less_or_equal(&mut lhs.ciphertext.borrow_mut(), scalar);
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn scalar_greater(
        &self,
        lhs: &GenericShortInt<P>,
        scalar: u8,
    ) -> GenericShortInt<P> {
        let ciphertext = self
            .key
            .scalar_greater(&mut lhs.ciphertext.borrow_mut(), scalar);
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn scalar_less(&self, lhs: &GenericShortInt<P>, scalar: u8) -> GenericShortInt<P> {
        let ciphertext = self
            .key
            .scalar_less(&mut lhs.ciphertext.borrow_mut(), scalar);
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn scalar_left_shift(
        &self,
        lhs: &GenericShortInt<P>,
        rhs: u8,
    ) -> GenericShortInt<P> {
        let ciphertext = self.key.scalar_left_shift(&lhs.ciphertext.borrow(), rhs);
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn scalar_right_shift(
        &self,
        lhs: &GenericShortInt<P>,
        rhs: u8,
    ) -> GenericShortInt<P> {
        let ciphertext = self.key.scalar_right_shift(&lhs.ciphertext.borrow(), rhs);
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn scalar_div(&self, lhs: &GenericShortInt<P>, rhs: u8) -> GenericShortInt<P> {
        let ciphertext = self.key.scalar_div(&lhs.ciphertext.borrow(), rhs);
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn scalar_mod(&self, lhs: &GenericShortInt<P>, rhs: u8) -> GenericShortInt<P> {
        let ciphertext = self.key.scalar_mod(&lhs.ciphertext.borrow(), rhs);
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn neg(&self, lhs: &GenericShortInt<P>) -> GenericShortInt<P> {
        let ciphertext = self.key.neg(&lhs.ciphertext.borrow());
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(super) fn bootstrap_with<F>(
        &self,
        ciphertext: &GenericShortInt<P>,
        func: F,
    ) -> GenericShortInt<P>
    where
        F: Fn(u64) -> u64,
    {
        let lookup_table = self.key.generate_lookup_table(func);
        let new_ciphertext = self
            .key
            .apply_lookup_table(&ciphertext.ciphertext.borrow(), &lookup_table);
        GenericShortInt {
            ciphertext: RefCell::new(new_ciphertext),
            id: ciphertext.id,
        }
    }

    pub(super) fn bootstrap_inplace_with<F>(&self, ciphertext: &GenericShortInt<P>, func: F)
    where
        F: Fn(u64) -> u64,
    {
        let lookup_table = self.key.generate_lookup_table(func);
        self.key
            .apply_lookup_table_assign(&mut ciphertext.ciphertext.borrow_mut(), &lookup_table)
    }

    pub(super) fn bivariate_pbs<F>(
        &self,
        lhs_ct: &GenericShortInt<P>,
        rhs_ct: &GenericShortInt<P>,
        func: F,
    ) -> GenericShortInt<P>
    where
        P: ShortIntegerParameter,
        F: Fn(u8, u8) -> u8,
    {
        let wrapped_f = |lhs: u64, rhs: u64| -> u64 { u64::from(func(lhs as u8, rhs as u8)) };

        let ciphertext = self.key.smart_evaluate_bivariate_function(
            &mut lhs_ct.ciphertext.borrow_mut(),
            &mut rhs_ct.ciphertext.borrow_mut(),
            wrapped_f,
        );
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs_ct.id,
        }
    }
}

#[cfg_attr(all(doc, not(doctest)), cfg(feature = "boolean"))]
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct GenericShortIntCompressedServerKey<P>
where
    P: ShortIntegerParameter,
{
    pub(in crate::high_level_api::shortints) key: CompressedServerKey,
    _marker: std::marker::PhantomData<P>,
}

impl<P> GenericShortIntCompressedServerKey<P>
where
    P: ShortIntegerParameter,
{
    pub(in crate::high_level_api::shortints) fn new(
        client_key: &GenericShortIntClientKey<P>,
    ) -> Self {
        Self {
            key: CompressedServerKey::new(&client_key.key),
            _marker: Default::default(),
        }
    }

    pub(in crate::high_level_api::shortints) fn decompress(self) -> GenericShortIntServerKey<P> {
        GenericShortIntServerKey {
            key: self.key.into(),
            _marker: std::marker::PhantomData,
        }
    }
}
