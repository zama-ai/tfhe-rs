use super::*;

// For the kogge stone add/sub
use crate::fw::rtl::{Rtl, VarCell};
use lazy_static::lazy_static;
use std::cmp::{Eq, PartialEq};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::io::Write;
use std::ops::Deref;
use std::sync::{Arc, RwLock};

use tracing::{trace, warn};

// For the kogge block table
use serde::{Deserialize, Serialize};
use toml;

#[derive(Clone, Serialize, Deserialize, Hash, PartialEq, Eq, Debug)]
struct KoggeBlockTableIndex(String);

impl From<FwParameters> for KoggeBlockTableIndex {
    fn from(value: FwParameters) -> Self {
        KoggeBlockTableIndex(format!("blk_{}_pbs_{}", value.blk_w(), value.pbs_batch_w))
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct KoggeBlockCfg {
    #[serde(skip)]
    filename: String,
    table: HashMap<KoggeBlockTableIndex, usize>,
}

fn append_bin(name: &str) -> String {
    let exe = env::current_exe().unwrap();
    let exe_dir = exe.parent().and_then(|p| p.to_str()).unwrap_or(".");
    format!("{}/{}", exe_dir, name)
}

impl KoggeBlockCfg {
    fn try_with_filename<F, E, R>(name: &str, f: F) -> Result<E, R>
    where
        F: Fn(&str) -> Result<E, R>,
    {
        f(name).or_else(|_| f(&append_bin(name)))
    }

    pub fn new(filename: &str) -> KoggeBlockCfg {
        if let Ok(contents) =
            KoggeBlockCfg::try_with_filename(filename, |f| std::fs::read_to_string(f))
        {
            let mut res: KoggeBlockCfg = toml::from_str(&contents)
                .unwrap_or_else(|_| panic!("{} is not a valid KoggeBlockCfg", filename));
            res.filename = String::from(filename);
            res
        } else {
            KoggeBlockCfg {
                filename: String::from(filename),
                table: HashMap::new(),
            }
        }
    }

    pub fn entry(&mut self, index: KoggeBlockTableIndex) -> Entry<'_, KoggeBlockTableIndex, usize> {
        self.table.entry(index)
    }

    pub fn get(&mut self, index: &KoggeBlockTableIndex) -> Option<&usize> {
        self.table.get(index)
    }

    fn try_write(&self) -> Result<(), Box<dyn Error>> {
        trace!(target: "rtl", "Saving {}", self.filename);
        // Convert in toml string
        let toml = toml::to_string(&self)?;

        // Open file and write to it
        let mut file = KoggeBlockCfg::try_with_filename(&self.filename, |name| {
            std::fs::File::options()
                .write(true)
                .truncate(true)
                .create(true)
                .open(name)
        })?;
        write!(&mut file, "{}", toml)?;
        Ok(())
    }
}

#[derive(Clone)]
struct KoggeBlockCfgPtr(Arc<RwLock<KoggeBlockCfg>>);

impl KoggeBlockCfgPtr {
    fn new(filename: &str) -> Self {
        KoggeBlockCfgPtr(Arc::new(RwLock::new(KoggeBlockCfg::new(filename))))
    }
}

impl Deref for KoggeBlockCfgPtr {
    type Target = RwLock<KoggeBlockCfg>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<&str> for KoggeBlockCfgPtr {
    fn from(cfg_f: &str) -> Self {
        let mut hash = KOGGE_BLOCK_CFG.write().unwrap();
        (hash
            .entry(cfg_f.to_string())
            .or_insert_with_key(|key| KoggeBlockCfgPtr::new(key)))
        .clone()
    }
}

lazy_static! {
    static ref KOGGE_BLOCK_CFG: Arc<RwLock<HashMap<String, KoggeBlockCfgPtr>>> =
        Arc::new(RwLock::new(HashMap::new()));
}

#[derive(Hash, PartialEq, Eq, Clone)]
struct Range(usize, usize);

#[derive(Clone, Debug)]
pub struct Carry {
    var: VarCell,
    cpos: usize,
    fresh: VarCell,
}

impl Carry {
    pub fn fresh(var: VarCell) -> Carry {
        Carry {
            var: var.clone(),
            cpos: 1,
            fresh: var,
        }
    }

    pub fn clone_on(&self, prog: &Program) -> Carry {
        Carry {
            var: self.var.clone_on(prog),
            cpos: self.cpos,
            fresh: self.fresh.clone_on(prog),
        }
    }
}

enum ReduceType {
    Simple(Pbs),
    Inc(Pbs),
}

impl ReduceType {
    fn apply(&self, var: &VarCell) -> VarCell {
        match self {
            ReduceType::Simple(pbs) => var.single_pbs(pbs),
            ReduceType::Inc(pbs) => &var.single_pbs(pbs) + 1,
        }
    }
}

struct KoggeTree {
    cache: HashMap<Range, Carry>,
    tfhe_params: asm::DigitParameters,
    reduce_map: HashMap<usize, ReduceType>,
}

impl KoggeTree {
    fn new(prg: &mut Program, inputs: Vec<Carry>) -> KoggeTree {
        let mut cache = HashMap::new();
        inputs.into_iter().enumerate().for_each(|(i, v)| {
            cache.insert(Range(i, i), v);
        });
        let props = prg.params();
        let tfhe_params: asm::DigitParameters = props.clone().into();
        let mut reduce_map = HashMap::new();
        reduce_map.insert(
            2,
            ReduceType::Simple(asm::Pbs::ReduceCarry2(asm::dop::PbsReduceCarry2::default())),
        );
        reduce_map.insert(
            3,
            ReduceType::Simple(asm::Pbs::ReduceCarry3(asm::dop::PbsReduceCarry3::default())),
        );
        reduce_map.insert(
            tfhe_params.total_width(),
            ReduceType::Inc(asm::Pbs::ReduceCarryPad(
                asm::dop::PbsReduceCarryPad::default(),
            )),
        );
        KoggeTree {
            cache,
            tfhe_params,
            reduce_map,
        }
    }

    fn get_subindex(&self, index: &Range) -> (Range, Range) {
        let range = index.1 - index.0 + 1;
        // Find the biggest power of two smaller than range
        let pow = 1 << range.ilog2();
        let mid = if pow == range {
            index.0 + (pow >> 1)
        } else {
            index.0 + pow
        };
        (Range(index.0, mid - 1), Range(mid, index.1))
    }

    fn insert_subtree(&mut self, index: &Range) {
        if !self.cache.contains_key(index) {
            let (lsb, msb) = self.get_subindex(index);
            self.insert_subtree(&lsb);
            self.insert_subtree(&msb);

            let (lsb, msb) = (self.cache.get(&lsb).unwrap(), self.cache.get(&msb).unwrap());
            let merge = {
                let cpos_trial = lsb.cpos + msb.cpos;
                let (lsb, msb, cpos, msb_shift) = if cpos_trial > self.tfhe_params.total_width() {
                    if msb.cpos + 1 > self.tfhe_params.total_width() {
                        (&lsb.fresh, &msb.fresh, 2, 2)
                    } else {
                        (&lsb.fresh, &msb.var, msb.cpos + 1, 2)
                    }
                } else {
                    (&lsb.var, &msb.var, cpos_trial, 1 << lsb.cpos)
                };

                let var = lsb.mac(msb_shift, msb);
                let fresh = self.reduce_map[&cpos].apply(&var);
                Carry { var, cpos, fresh }
            };

            self.cache.insert((*index).clone(), merge);
        }
    }

    fn get_subtree(&mut self, index: &Range) -> &Carry {
        self.insert_subtree(index);
        self.cache.get(index).unwrap()
    }
}

// Receives cypher texts with carry (in carry save form) and outputs cypher
// texts with carry propagated. The first item in the input vector is the carry
// in.
// Calling this only makes sense if the generated PBSs fit nicely into the batch
// size.
#[instrument(level = "trace", skip(prog))]
pub fn propagate_carry(
    prog: &mut Program,
    dst: &mut [VarCell],
    carrysave: &[VarCell],
    cin: &Option<Carry>,
) -> Carry {
    let tfhe_params: asm::DigitParameters = prog.params().clone().into();

    let pbs_genprop = asm::Pbs::ManyGenProp(asm::dop::PbsManyGenProp::default());
    let pbs_genprop_add = asm::Pbs::GenPropAdd(asm::dop::PbsGenPropAdd::default());

    // Make sure the TFHE parameters are enough to run this
    assert!(
        tfhe_params.total_width() >= 3,
        "Cannot run Kogge stone with a total message width less than 3"
    );

    // Split the result into message and propagate/generate information using a
    // manyLUT
    let (msg, mut carry): (Vec<_>, Vec<_>) = carrysave
        .iter()
        .map(|v| {
            let mut res = v.pbs(&pbs_genprop).into_iter();
            (res.next().unwrap(), Carry::fresh(res.next().unwrap()))
        })
        .unzip();

    // Add the carry in as the first carry if any
    carry.insert(
        0,
        cin.clone()
            .unwrap_or_else(|| Carry::fresh(VarCell::from(prog.new_imm(0)))),
    );

    // Build a list of terminal outputs
    let mut carry_tree = KoggeTree::new(prog, carry);

    for i in 0..msg.len() {
        let subtree = carry_tree.get_subtree(&Range(0, i));
        let mac = msg[i].mac(tfhe_params.msg_range(), &subtree.fresh);
        let pbs = mac.single_pbs(&pbs_genprop_add);
        dst[i] <<= &pbs;
    }

    carry_tree.get_subtree(&Range(0, msg.len())).clone()
}

// Adds two vectors of VarCells and produces a register transfer level
// description of a kogge stone adder that can then be added to the program
pub fn add(
    prog: &mut Program,
    a: Vec<VarCell>,
    b: Vec<VarCell>,
    mut cin: Option<Carry>,
    mut dst: Vec<VarCell>,
    par_w: usize,
) -> Rtl {
    // Carry save add
    let csave: Vec<_> = a
        .into_iter()
        .zip_longest(b)
        .map(|r| match r {
            EitherOrBoth::Left(x) | EitherOrBoth::Right(x) => x,
            EitherOrBoth::Both(a, b) => &a + &b,
        })
        .collect();

    (0..csave.len().div_ceil(par_w)).for_each(|chunk_idx| {
        let start = chunk_idx * par_w;
        let end = (start + par_w).min(csave.len());
        cin = Some(kogge::propagate_carry(
            prog,
            &mut dst[start..],
            &csave[start..end],
            &cin,
        ));
    });

    Rtl::from(dst)
}

pub fn sub(
    prog: &mut Program,
    a: Vec<VarCell>,
    b: Vec<VarCell>,
    dst: Vec<VarCell>,
    par_w: usize,
) -> Rtl {
    let b_inv = bw_inv(prog, b);
    let one = Carry::fresh(VarCell::from(prog.new_imm(2)));
    kogge::add(prog, a, b_inv, Some(one), dst, par_w)
}

// cached kogge_adder wrapper
// This finds the best par_w for the given architecture and caches the result
pub fn cached_add(
    prog: &mut Program,
    a: Vec<VarCell>,
    b: Vec<VarCell>,
    cin: Option<Carry>,
    dst: Vec<metavar::MetaVarCell>,
) -> Rtl {
    let kogge_cfg_ptr = KoggeBlockCfgPtr::from(prog.params().kogge_cfg.as_str());
    let mut kogge_cfg = kogge_cfg_ptr.write().unwrap();
    let index: KoggeBlockTableIndex = prog.params().into();
    let dst: Vec<_> = dst.iter().map(|v| VarCell::from(v.clone())).collect();
    let clone_on = |prog: &Program, v: &Vec<VarCell>| v.iter().map(|v| v.clone_on(prog)).collect();
    let mut dirty = false;

    trace!(target: "rtl", "kogge config: {:?}", kogge_cfg);

    kogge_cfg
        .get(&index)
        .copied()
        .or_else(|| {
            dirty = true;
            (1..=prog.params().blk_w())
                .map(|w| {
                    // Build a new tree for every par_w trial, which means that we
                    // need to get fresh variables for each trial.
                    let mut tmp_prog = Program::new(&prog.params());
                    let a: Vec<_> = clone_on(&tmp_prog, &a);
                    let b: Vec<_> = clone_on(&tmp_prog, &b);
                    let dst: Vec<_> = clone_on(&tmp_prog, &dst);
                    let cin = cin.clone().map(|c| c.clone_on(&tmp_prog));
                    let tree = add(&mut tmp_prog, a, b, cin, dst, w);
                    (w, tree.estimate(&tmp_prog))
                })
                .min_by_key(|(_, cycle_estimate)| *cycle_estimate)
                .map(|(w, _)| w)
        })
        .map(|w| {
            kogge_cfg.entry(index).or_insert(w);
            if dirty && kogge_cfg.try_write().is_err() {
                warn!("Could not write kogge config");
            }
            add(prog, a, b, cin, dst, w)
        })
        .unwrap()
}
