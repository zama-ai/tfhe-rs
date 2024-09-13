//!
//! Abstraction used to ease FW writing
//!
//! It provide a set of utilities used to help FW implementation
//! with a clean and easy to read API

use lru::LruCache;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use crate::asm::arg::{Arg, MemMode, MemOrigin};
use crate::asm::dop::DOp;
use crate::asm::pbs::DigitParameters;
use crate::asm::{ArchProperties, MemSlot};

use super::metavar::{MetaVarCell, MetaVarCellWeak};

#[derive(Debug)]
pub struct ProgramInner {
    uid: usize,
    pub(crate) props: ArchProperties,
    pub(crate) regs: LruCache<usize, Option<MetaVarCellWeak>>,
    pub(crate) heap: LruCache<MemSlot, Option<MetaVarCellWeak>>,
    pub(crate) vars: HashMap<usize, MetaVarCellWeak>,
    pub(crate) stmts: Vec<DOp>,
}

/// ProgramInner constructors
impl ProgramInner {
    pub fn new(props: &ArchProperties) -> Self {
        let nb_regs = match std::num::NonZeroUsize::try_from(props.regs) {
            Ok(val) => val,
            _ => panic!("Error: Number of registers must be >= 0"),
        };
        let mut regs = LruCache::<usize, Option<MetaVarCellWeak>>::new(nb_regs);
        // At start regs cache is full of unused slot
        for rid in 0..props.regs {
            regs.put(rid, None);
        }

        let nb_heap = match std::num::NonZeroUsize::try_from(props.mem.size) {
            Ok(val) => val,
            _ => panic!("Error: Number of heap slot must be >= 0"),
        };
        let mut heap = LruCache::<MemSlot, Option<MetaVarCellWeak>>::new(nb_heap);
        // At start heap cache is full of unused slot
        // TODO add user define bid
        for cid in 0..props.mem.size {
            heap.put(
                MemSlot::new(props, 0, cid, MemMode::Template, Some(MemOrigin::Heap)).unwrap(),
                None,
            );
        }

        Self {
            uid: 0,
            props: props.clone(),
            regs,
            heap,
            vars: HashMap::new(),
            stmts: Vec::new(),
        }
    }
}

/// Cache handling
impl ProgramInner {
    /// Retrieved least-recent-used register entry
    /// Return associated register id and evicted variable if any
    /// Warn: Keep cache state unchanged ...
    fn reg_lru(&mut self) -> (usize, Option<MetaVarCell>) {
        let (rid, rdata) = self
            .regs
            .peek_lru()
            .expect("Error: register cache empty. Check register management");

        // Handle evicted slot if any
        // Convert it in strong reference for later handling
        let evicted = if let Some(weak_evicted) = rdata {
            match weak_evicted.try_into() {
                Ok(cell) => Some(cell),
                Err(_) => None,
            }
        } else {
            None
        };

        (*rid, evicted)
    }

    /// Release register entry
    pub(crate) fn reg_release(&mut self, rid: usize) {
        *(self
            .regs
            .get_mut(&rid)
            .expect("Release an `unused` register")) = None;

        // Update cache state
        // Put this slot in front of all `empty` slot instead of in lru pos
        self.regs.promote(&rid);
        let demote_order = self
            .regs
            .iter()
            .filter(|(_, var)| var.is_none())
            .map(|(rid, _)| *rid)
            .collect::<Vec<_>>();
        demote_order
            .into_iter()
            .for_each(|rid| self.regs.demote(&rid));
    }

    /// Notify register access to update LRU state
    pub(crate) fn reg_access(&mut self, rid: usize) {
        self.regs.promote(&rid)
    }

    /// Insert MetaVar in cache and return evicted value if any
    pub(crate) fn reg_swap_lru(&mut self, var: MetaVarCell) -> (usize, Option<MetaVarCell>) {
        // Find lru slot
        let (rid, evicted) = self.reg_lru();

        // Update cache state
        *(self
            .regs
            .get_mut(&rid)
            .expect("Update an `unused` register")) = Some((&var).into());

        (rid, evicted)
    }

    /// Retrieved least-recent-used heap entry
    /// Return associated heap id and evicted variable if any
    /// Warn: Keep cache state unchanged ...
    fn heap_lru(&mut self) -> (MemSlot, Option<MetaVarCell>) {
        let (mid, rdata) = self
            .heap
            .peek_lru()
            .expect("Error: heap cache empty. Check register management");

        // Handle evicted slot if any
        // Convert it in strong reference for later handling
        let evicted = if let Some(weak_evicted) = rdata {
            match weak_evicted.try_into() {
                Ok(cell) => Some(cell),
                Err(_) => None,
            }
        } else {
            None
        };

        (*mid, evicted)
    }

    /// Release register entry
    pub(crate) fn heap_release(&mut self, mid: MemSlot) {
        // Check if slot belong to heap
        if mid.orig().is_none() {
            *(self
                .heap
                .get_mut(&mid)
                .expect("Release an `unused` heap slot")) = None;
            // Update cache state
            // Put this slot in front of all `empty` slot instead of in lru pos
            self.heap.promote(&mid);
            let demote_order = self
                .heap
                .iter()
                .filter(|(_mid, var)| var.is_none())
                .map(|(mid, _)| *mid)
                .collect::<Vec<_>>();
            demote_order
                .into_iter()
                .for_each(|mid| self.heap.demote(&mid));
        }
    }

    /// Notify heap access to update LRU state
    pub(crate) fn heap_access(&mut self, mid: MemSlot) {
        self.heap.promote(&mid);
    }

    /// Insert MetaVar in cache and return evicted value if any
    pub(crate) fn heap_swap_lru(&mut self, var: MetaVarCell) -> (MemSlot, Option<MetaVarCell>) {
        // Find lru slot
        let (mid, evicted) = self.heap_lru();

        // Update cache state
        *(self
            .heap
            .get_mut(&mid)
            .expect("Update an `unused` heap slot")) = Some((&var).into());

        (mid, evicted)
    }
}

/// MetaVar handling
impl ProgramInner {
    /// Create MetaVar from an optional argument
    /// Hack around to have access to a reference to RefCell Wrapped
    fn var_from(&mut self, from: Option<Arg>, ref_to_self: Rc<RefCell<Self>>) -> MetaVarCell {
        // Create MetaVar
        let uid = self.uid;
        self.uid += 1;

        // Construct tfhe params
        let tfhe_params: DigitParameters = self.props.clone().into();
        let var = MetaVarCell::new(ref_to_self, uid, from, tfhe_params);

        // Register in var store
        self.vars.insert(uid, (&var).into());

        var
    }

    pub fn new_var(&mut self, ref_to_self: Rc<RefCell<Self>>) -> MetaVarCell {
        self.var_from(None, ref_to_self)
    }
}

pub struct Program {
    inner: Rc<RefCell<ProgramInner>>,
}

impl Program {
    pub fn new(props: &ArchProperties) -> Self {
        Self {
            inner: Rc::new(RefCell::new(ProgramInner::new(props))),
        }
    }

    pub fn props(&self) -> ArchProperties {
        self.inner.borrow().props.clone()
    }

    pub fn get_stmts(&self) -> Vec<DOp> {
        self.inner.borrow().stmts.clone()
    }

    pub fn var_from(&mut self, from: Option<Arg>) -> MetaVarCell {
        let inner_clone = self.inner.clone();
        self.inner.borrow_mut().var_from(from, inner_clone)
    }

    pub fn new_var(&mut self) -> MetaVarCell {
        self.var_from(None)
    }

    /// Easy way to create new imm value
    pub fn new_imm(&mut self, imm: usize) -> MetaVarCell {
        let arg = Some(Arg::Imm(imm));
        self.var_from(arg)
    }

    /// Easy way to create constant backed in register
    pub fn new_cst(&mut self, cst: usize) -> MetaVarCell {
        let mut var = self.var_from(None);
        var.reg_alloc_mv();
        // Force val to 0 then add cst value
        var -= var.clone();
        if cst != 0 {
            let imm = self.new_imm(cst);
            var += imm;
        }

        var
    }

    /// Take User argument (i.e. IOp MemId) and convert it program arg (i.e. vector of DOp MemId)
    /// User var will be used through Templated ops, thus bid/cid information is removed
    pub fn user_var(&mut self, arg: Arg) -> Vec<MetaVarCell> {
        let nb_blk = self.inner.borrow().props.blk_w();
        match arg {
            Arg::MemId(hid) => {
                // Digit in user arg are contiguous
                (0..nb_blk)
                    .map(|i| {
                        let cur_hid = MemSlot::new(
                            &self.props(),
                            0,
                            i,
                            MemMode::Template,
                            hid.orig().clone(),
                        )
                        .unwrap();
                        self.var_from(Some(Arg::MemId(cur_hid)))
                    })
                    .collect::<Vec<_>>()
            }
            Arg::Imm(scalar) => {
                // Slice scalar in digit
                (0..nb_blk)
                    .map(|i| {
                        let msg_w = self.props().msg_w;
                        let mask = (1 << self.props().msg_w) - 1;
                        let cur_s = (scalar >> (i * msg_w)) & mask;
                        self.var_from(Some(Arg::Imm(cur_s)))
                    })
                    .collect::<Vec<_>>()
            }
            _ => panic!("User_var required MemId||Imm argument"),
        }
    }

    /// Bulk reserve
    /// Evict value from cache in a bulk manner. This enable to prevent false dependency of bulk
    /// opertions when cache is almost full Enforce that at least bulk_size register is `free`
    pub(crate) fn reg_bulk_reserve(&self, bulk_size: usize) {
        // Iter from Lru -> MRu and take bulk_size regs
        let to_evict = self
            .inner
            .borrow()
            .regs
            .iter()
            .rev()
            .take(bulk_size)
            .filter(|(_, var)| var.is_some())
            .map(|(_, var)| var.as_ref().unwrap().clone())
            .collect::<Vec<_>>();

        // Evict metavar to heap and release
        to_evict.into_iter().for_each(|var| {
            // Evict in memory if needed
            if let Ok(cell) = MetaVarCell::try_from(&var) {
                cell.heap_alloc_mv(true);
            }
        });
    }

    pub fn write_asm(&self, asm_f: &str, header: &str, width: usize) {
        let inner = self.inner.borrow();
        crate::asm::write_asm(header, inner.stmts.as_slice(), asm_f, width).unwrap()
    }

    pub fn write_hex(&self, hex_f: &str, header: &str) {
        let inner = self.inner.borrow();
        crate::asm::write_hex(header, inner.stmts.as_slice(), hex_f).unwrap()
    }

    /// Convert prog in translation table
    pub fn tr_table(&self) -> Vec<u32> {
        let inner = self.inner.borrow();
        crate::asm::tr_table(&inner.stmts)
    }
}

/// Syntax sugar to help user wrap PbsLut in MetaVarCell
#[macro_export]
macro_rules! new_pbs {
    (
        $prog:ident, $pbs: literal
    ) => {
        ::paste::paste! {
            $prog.var_from(Some(Arg::Pbs(asm::[<Pbs $pbs:camel>]::default().into())))
        }
    };
}
