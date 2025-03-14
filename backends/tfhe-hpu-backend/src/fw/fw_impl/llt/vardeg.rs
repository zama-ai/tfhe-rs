use super::rtl::VarCell;
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
    pub fn deg_chunks(
        mut self,
        max_deg: &VarDeg,
    ) -> <Vec<Vec<VarCellDeg>> as IntoIterator>::IntoIter {
        trace!(target: "ilp:deg_chunks", "len: {:?}, {:?}", self.len(), self.0);

        let mut res: Vec<Vec<VarCellDeg>> = Vec::new();
        let mut acc: VarDeg = VarDeg::default();
        let mut chunk: Vec<VarCellDeg> = Vec::new();

        // There are many ways to combine the whole vector in chunks up to
        // max_deg. We'll be greedy and sum up the elements by maximum degree
        // first.
        self.0.sort();

        while !self.is_empty() {
            let sum = &acc + &self.0.last().unwrap().deg;
            if sum <= *max_deg {
                chunk.push(self.0.pop().unwrap());
                acc = sum;
            } else {
                res.push(chunk);
                acc = VarDeg::default();
                chunk = Vec::new();
            }
            trace!(target: "ilp:deg_chunks:loop", "len: {:?}, {:?}, chunk: {:?},
                acc: {:?}", self.len(), self.0, chunk, acc);
        }

        // Any remaining chunk is appended
        if !chunk.is_empty() {
            res.push(chunk);
        }

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
}
