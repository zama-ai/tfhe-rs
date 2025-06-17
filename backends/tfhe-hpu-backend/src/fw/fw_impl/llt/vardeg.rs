use super::rtl::VarCell;
use super::*;
use crate::pbs_by_name;
use tracing::trace;

#[derive(Clone, Eq, Default, Debug)]
pub struct VarDeg {
    pub deg: usize,
    pub nu: usize,
}

impl std::ops::Add for &VarDeg {
    type Output = VarDeg;

    fn add(self, rhs: Self) -> Self::Output {
        VarDeg {
            deg: self.deg + rhs.deg,
            nu: self.nu + rhs.nu,
        }
    }
}

impl PartialOrd for VarDeg {
    fn partial_cmp(&self, other: &VarDeg) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for VarDeg {
    fn cmp(&self, other: &VarDeg) -> std::cmp::Ordering {
        if self.deg > other.deg || self.nu > other.nu {
            std::cmp::Ordering::Greater
        } else if self.deg == other.deg || self.nu == other.nu {
            std::cmp::Ordering::Equal
        } else {
            std::cmp::Ordering::Less
        }
    }
}

impl PartialEq for VarDeg {
    fn eq(&self, other: &VarDeg) -> bool {
        self.cmp(other) == std::cmp::Ordering::Equal
    }
}

#[derive(Clone, Eq)]
pub struct VarCellDeg {
    pub var: VarCell,
    pub deg: VarDeg,
}

impl VarCellDeg {
    pub fn bootstrap(&self, props: &FwParameters) -> (VarCellDeg, Option<VarCellDeg>) {
        trace!(target: "vardeg::VarCellDeg::bootstrap", "bootstrap: {:?}", self);

        let pbs_many_carry = pbs_by_name!("ManyCarryMsg");
        let pbs_carry = pbs_by_name!("CarryInMsg");
        let pbs_msg = pbs_by_name!("MsgOnly");

        if self.deg.deg <= props.max_msg() {
            match self.deg.nu {
                1 => (self.clone(), None),
                _ => (
                    VarCellDeg::new(self.deg.deg, self.var.single_pbs(&pbs_msg)),
                    None,
                ),
            }
        // If we still have a bit available to do manyLUT
        } else if self.deg.deg > props.max_msg() && self.deg.deg <= (props.max_val() >> 1) {
            let mut pbs = self.var.pbs(&pbs_many_carry).into_iter();
            (
                VarCellDeg::new(props.max_msg().min(self.deg.deg), pbs.next().unwrap()),
                Some(VarCellDeg::new(
                    self.deg.deg >> props.carry_w,
                    pbs.next().unwrap(),
                )),
            )
        //Otherwise, we'll have to use two independent PBSs
        } else {
            (
                VarCellDeg::new(
                    self.deg.deg.min(props.max_msg()),
                    self.var.single_pbs(&pbs_msg),
                ),
                Some(VarCellDeg::new(
                    self.deg.deg >> props.carry_w,
                    self.var.single_pbs(&pbs_carry),
                )),
            )
        }
    }
}

impl PartialOrd for VarCellDeg {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for VarCellDeg {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.deg.cmp(&other.deg)
    }
}

impl PartialEq for VarCellDeg {
    fn eq(&self, other: &VarCellDeg) -> bool {
        self.cmp(other) == std::cmp::Ordering::Equal
    }
}

impl std::ops::Add for &VarCellDeg {
    type Output = VarCellDeg;

    fn add(self, rhs: Self) -> Self::Output {
        VarCellDeg {
            var: &self.var + &rhs.var,
            deg: &self.deg + &rhs.deg,
        }
    }
}

impl VarCellDeg {
    pub fn new(deg: usize, var: VarCell) -> Self {
        VarCellDeg {
            var,
            deg: VarDeg { deg, nu: 1 },
        }
    }
}

#[derive(Debug)]
pub struct VecVarCellDeg(pub Vec<VarCellDeg>);

impl From<Vec<VarCellDeg>> for VecVarCellDeg {
    fn from(v: Vec<VarCellDeg>) -> Self {
        VecVarCellDeg(v)
    }
}

impl std::fmt::Debug for VarCellDeg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VarCellDeg")
            .field("deg", &self.deg.deg)
            .field("nu", &self.deg.nu)
            .finish()
    }
}

impl VecVarCellDeg {
    pub fn deg_chunks(&self, max_deg: &VarDeg) -> <Vec<Vec<VarCellDeg>> as IntoIterator>::IntoIter {
        trace!(target: "llt:deg_chunks", "len: {:?}, {:?}", self.len(), self.0);

        let mut res: Vec<Vec<VarCellDeg>> = Vec::new();
        let mut acc: VarDeg = VarDeg::default();
        let mut chunk: Vec<VarCellDeg> = Vec::new();
        let mut copy = self.0.clone();

        // There are many ways to combine the whole vector in chunks up to
        // max_deg. We'll be greedy and sum up the elements by maximum degree
        // first.
        copy.sort();

        while !copy.is_empty() {
            let sum = &acc + &copy.last().unwrap().deg;
            if sum <= *max_deg {
                chunk.push(copy.pop().unwrap());
                acc = sum;
            } else {
                res.push(chunk);
                acc = VarDeg::default();
                chunk = Vec::new();
            }
            trace!(target: "llt:deg_chunks:loop", "len: {:?}, {:?}, chunk: {:?}, acc: {:?}",
                self.len(), copy, chunk, acc);
        }

        // Any remaining chunk is appended
        if !chunk.is_empty() {
            res.push(chunk);
        }

        trace!(target: "llt:deg_chunks:ret", "res: {:?}", res);

        res.into_iter()
    }

    pub fn first(self) -> Option<VarCellDeg> {
        self.0.into_iter().next()
    }

    pub fn max_mut(&mut self) -> Option<&mut VarCellDeg> {
        self.0.iter_mut().max()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.len() == 0
    }

    pub fn push(&mut self, item: VarCellDeg) {
        self.0.push(item)
    }
}
