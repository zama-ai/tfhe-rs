use std::cell::RefCell;
use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

#[cfg(feature = "internal-keycache")]
use crate::shortint::keycache::KEY_CACHE;
use crate::shortint::ServerKey;

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
        let key = KEY_CACHE
            .get_from_param(client_key.key.parameters)
            .server_key()
            .clone();
        #[cfg(not(feature = "internal-keycache"))]
        let key = ServerKey::new(&client_key.key);

        Self {
            key,
            _marker: Default::default(),
        }
    }

    pub(crate) fn smart_add(
        &self,
        lhs: &GenericShortInt<P>,
        rhs: &GenericShortInt<P>,
    ) -> GenericShortInt<P> {
        let ciphertext = self.key.smart_add(
            &mut lhs.ciphertext.borrow_mut(),
            &mut rhs.ciphertext.borrow_mut(),
        );
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn smart_sub(
        &self,
        lhs: &GenericShortInt<P>,
        rhs: &GenericShortInt<P>,
    ) -> GenericShortInt<P> {
        let ciphertext = self.key.smart_sub(
            &mut lhs.ciphertext.borrow_mut(),
            &mut rhs.ciphertext.borrow_mut(),
        );
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn smart_mul(
        &self,
        lhs: &GenericShortInt<P>,
        rhs: &GenericShortInt<P>,
    ) -> GenericShortInt<P> {
        let ciphertext = self.key.smart_mul_lsb(
            &mut lhs.ciphertext.borrow_mut(),
            &mut rhs.ciphertext.borrow_mut(),
        );
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn smart_div(
        &self,
        lhs: &GenericShortInt<P>,
        rhs: &GenericShortInt<P>,
    ) -> GenericShortInt<P> {
        let ciphertext = self.key.smart_div(
            &mut lhs.ciphertext.borrow_mut(),
            &mut rhs.ciphertext.borrow_mut(),
        );
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn smart_add_assign(&self, lhs: &GenericShortInt<P>, rhs: &GenericShortInt<P>) {
        self.key.smart_add_assign(
            &mut lhs.ciphertext.borrow_mut(),
            &mut rhs.ciphertext.borrow_mut(),
        );
    }

    pub(crate) fn smart_sub_assign(&self, lhs: &GenericShortInt<P>, rhs: &GenericShortInt<P>) {
        self.key.smart_sub_assign(
            &mut lhs.ciphertext.borrow_mut(),
            &mut rhs.ciphertext.borrow_mut(),
        );
    }

    pub(crate) fn smart_mul_assign(&self, lhs: &GenericShortInt<P>, rhs: &GenericShortInt<P>) {
        self.key.smart_mul_lsb_assign(
            &mut lhs.ciphertext.borrow_mut(),
            &mut rhs.ciphertext.borrow_mut(),
        );
    }

    pub(crate) fn smart_div_assign(&self, lhs: &GenericShortInt<P>, rhs: &GenericShortInt<P>) {
        self.key.smart_div_assign(
            &mut lhs.ciphertext.borrow_mut(),
            &mut rhs.ciphertext.borrow_mut(),
        )
    }

    pub(crate) fn smart_bitand_assign(&self, lhs: &GenericShortInt<P>, rhs: &GenericShortInt<P>) {
        self.key.smart_bitand_assign(
            &mut lhs.ciphertext.borrow_mut(),
            &mut rhs.ciphertext.borrow_mut(),
        );
    }

    pub(crate) fn smart_bitor_assign(&self, lhs: &GenericShortInt<P>, rhs: &GenericShortInt<P>) {
        self.key.smart_bitor_assign(
            &mut lhs.ciphertext.borrow_mut(),
            &mut rhs.ciphertext.borrow_mut(),
        );
    }

    pub(crate) fn smart_bitxor_assign(&self, lhs: &GenericShortInt<P>, rhs: &GenericShortInt<P>) {
        self.key.smart_bitxor_assign(
            &mut lhs.ciphertext.borrow_mut(),
            &mut rhs.ciphertext.borrow_mut(),
        );
    }

    pub(crate) fn smart_scalar_sub(&self, lhs: &GenericShortInt<P>, rhs: u8) -> GenericShortInt<P> {
        let ciphertext = self
            .key
            .smart_scalar_sub(&mut lhs.ciphertext.borrow_mut(), rhs);
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn smart_scalar_mul(&self, lhs: &GenericShortInt<P>, rhs: u8) -> GenericShortInt<P> {
        let ciphertext = self
            .key
            .smart_scalar_mul(&mut lhs.ciphertext.borrow_mut(), rhs);
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn smart_scalar_add(
        &self,
        lhs: &GenericShortInt<P>,
        scalar: u8,
    ) -> GenericShortInt<P> {
        let ciphertext = self
            .key
            .smart_scalar_add(&mut lhs.ciphertext.borrow_mut(), scalar);
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn smart_scalar_add_assign(&self, lhs: &mut GenericShortInt<P>, rhs: u8) {
        self.key
            .smart_scalar_add_assign(&mut lhs.ciphertext.borrow_mut(), rhs)
    }

    pub(crate) fn smart_scalar_mul_assign(&self, lhs: &mut GenericShortInt<P>, rhs: u8) {
        self.key
            .smart_scalar_mul_assign(&mut lhs.ciphertext.borrow_mut(), rhs)
    }

    pub(crate) fn smart_scalar_sub_assign(&self, lhs: &mut GenericShortInt<P>, rhs: u8) {
        self.key
            .smart_scalar_sub_assign(&mut lhs.ciphertext.borrow_mut(), rhs)
    }

    pub(crate) fn smart_bitand(
        &self,
        lhs: &GenericShortInt<P>,
        rhs: &GenericShortInt<P>,
    ) -> GenericShortInt<P> {
        let ciphertext = self.key.smart_bitand(
            &mut lhs.ciphertext.borrow_mut(),
            &mut rhs.ciphertext.borrow_mut(),
        );
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn smart_bitor(
        &self,
        lhs: &GenericShortInt<P>,
        rhs: &GenericShortInt<P>,
    ) -> GenericShortInt<P> {
        let ciphertext = self.key.smart_bitor(
            &mut lhs.ciphertext.borrow_mut(),
            &mut rhs.ciphertext.borrow_mut(),
        );
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn smart_bitxor(
        &self,
        lhs: &GenericShortInt<P>,
        rhs: &GenericShortInt<P>,
    ) -> GenericShortInt<P> {
        let ciphertext = self.key.smart_bitxor(
            &mut lhs.ciphertext.borrow_mut(),
            &mut rhs.ciphertext.borrow_mut(),
        );
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn smart_less(
        &self,
        lhs: &GenericShortInt<P>,
        rhs: &GenericShortInt<P>,
    ) -> GenericShortInt<P> {
        let ciphertext = self.key.smart_less(
            &mut lhs.ciphertext.borrow_mut(),
            &mut rhs.ciphertext.borrow_mut(),
        );
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn smart_less_or_equal(
        &self,
        lhs: &GenericShortInt<P>,
        rhs: &GenericShortInt<P>,
    ) -> GenericShortInt<P> {
        let ciphertext = self.key.smart_less_or_equal(
            &mut lhs.ciphertext.borrow_mut(),
            &mut rhs.ciphertext.borrow_mut(),
        );
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn smart_greater(
        &self,
        lhs: &GenericShortInt<P>,
        rhs: &GenericShortInt<P>,
    ) -> GenericShortInt<P> {
        let ciphertext = self.key.smart_greater(
            &mut lhs.ciphertext.borrow_mut(),
            &mut rhs.ciphertext.borrow_mut(),
        );
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn smart_greater_or_equal(
        &self,
        lhs: &GenericShortInt<P>,
        rhs: &GenericShortInt<P>,
    ) -> GenericShortInt<P> {
        let ciphertext = self.key.smart_greater_or_equal(
            &mut lhs.ciphertext.borrow_mut(),
            &mut rhs.ciphertext.borrow_mut(),
        );
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn smart_equal(
        &self,
        lhs: &GenericShortInt<P>,
        rhs: &GenericShortInt<P>,
    ) -> GenericShortInt<P> {
        let ciphertext = self.key.smart_equal(
            &mut lhs.ciphertext.borrow_mut(),
            &mut rhs.ciphertext.borrow_mut(),
        );
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn smart_scalar_equal(
        &self,
        lhs: &GenericShortInt<P>,
        scalar: u8,
    ) -> GenericShortInt<P> {
        let ciphertext = self
            .key
            .smart_scalar_equal(&lhs.ciphertext.borrow(), scalar);
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn smart_scalar_greater_or_equal(
        &self,
        lhs: &GenericShortInt<P>,
        scalar: u8,
    ) -> GenericShortInt<P> {
        let ciphertext = self
            .key
            .smart_scalar_greater_or_equal(&lhs.ciphertext.borrow(), scalar);
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn smart_scalar_less_or_equal(
        &self,
        lhs: &GenericShortInt<P>,
        scalar: u8,
    ) -> GenericShortInt<P> {
        let ciphertext = self
            .key
            .smart_scalar_less_or_equal(&lhs.ciphertext.borrow(), scalar);
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn smart_scalar_greater(
        &self,
        lhs: &GenericShortInt<P>,
        scalar: u8,
    ) -> GenericShortInt<P> {
        let ciphertext = self
            .key
            .smart_scalar_greater(&lhs.ciphertext.borrow(), scalar);
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn smart_scalar_less(
        &self,
        lhs: &GenericShortInt<P>,
        scalar: u8,
    ) -> GenericShortInt<P> {
        let ciphertext = self.key.smart_scalar_less(&lhs.ciphertext.borrow(), scalar);
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn smart_scalar_left_shift(
        &self,
        lhs: &GenericShortInt<P>,
        rhs: u8,
    ) -> GenericShortInt<P> {
        let ciphertext = self
            .key
            .smart_scalar_left_shift(&mut lhs.ciphertext.borrow_mut(), rhs);
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn unchecked_scalar_right_shift(
        &self,
        lhs: &GenericShortInt<P>,
        rhs: u8,
    ) -> GenericShortInt<P> {
        let ciphertext = self
            .key
            .unchecked_scalar_right_shift(&lhs.ciphertext.borrow(), rhs);
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn unchecked_scalar_div(
        &self,
        lhs: &GenericShortInt<P>,
        rhs: u8,
    ) -> GenericShortInt<P> {
        let ciphertext = self.key.unchecked_scalar_div(&lhs.ciphertext.borrow(), rhs);
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn unchecked_scalar_mod(
        &self,
        lhs: &GenericShortInt<P>,
        rhs: u8,
    ) -> GenericShortInt<P> {
        let ciphertext = self.key.unchecked_scalar_mod(&lhs.ciphertext.borrow(), rhs);
        GenericShortInt {
            ciphertext: RefCell::new(ciphertext),
            id: lhs.id,
        }
    }

    pub(crate) fn smart_neg(&self, lhs: &GenericShortInt<P>) -> GenericShortInt<P> {
        let ciphertext = self.key.smart_neg(&mut lhs.ciphertext.borrow_mut());
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
        let accumulator = self.key.generate_accumulator(func);
        let new_ciphertext = self
            .key
            .keyswitch_programmable_bootstrap(&ciphertext.ciphertext.borrow(), &accumulator);
        GenericShortInt {
            ciphertext: RefCell::new(new_ciphertext),
            id: ciphertext.id,
        }
    }

    pub(super) fn bootstrap_inplace_with<F>(&self, ciphertext: &mut GenericShortInt<P>, func: F)
    where
        F: Fn(u64) -> u64,
    {
        let accumulator = self.key.generate_accumulator(func);
        self.key.keyswitch_programmable_bootstrap_assign(
            &mut ciphertext.ciphertext.borrow_mut(),
            &accumulator,
        )
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

        let ciphertext = self.key.smart_functional_bivariate_pbs(
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
