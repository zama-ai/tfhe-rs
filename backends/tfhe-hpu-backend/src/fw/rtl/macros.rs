#[macro_export]
macro_rules! rtl_op {
    (
        $name: literal,
        $kind: ident,
        $($data: ident,)?
        ($this:ident, $prog:tt) $add:block
    ) => {
        ::paste::paste! {
            #[derive(Debug, Clone)]
            pub struct [<$name:camel Op>] {
                src: Vec<VarCell>,
                dst: Vec<Option<VarCell>>,
                uid: usize,
                load_stats: Option<LoadStats>,
                $(data: $data)*
            }

            impl std::hash::Hash for [<$name:camel Op>] {
                fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
                    self.uid.hash(state);
                }
            }

            impl std::cmp::PartialEq for [<$name:camel Op>] {
                fn eq(&self, other: &[<$name:camel Op>]) -> bool {
                    self.uid == other.uid
                }
            }

            impl std::cmp::Eq for [<$name:camel Op>] { }

            impl std::ops::Drop for [<$name:camel Op>] {
                fn drop(&mut self) {
                    trace!(target: "rtl", "Operation Dropped: {:?}", &self);
                }
            }

            impl OperationTrait for [<$name:camel Op>] {
                fn name(&self) -> &str {
                    $name
                }
                fn kind(&self) -> InstructionKind {
                    InstructionKind::$kind
                }

                fn get_meta_var(&$this, prog: &mut Option<Program>) -> Vec<MetaVarCell> {
                    if let Some($prog) = prog {
                        $add
                    } else {
                        (0..$this.dst.len())
                            .map(|_| $this.src[0].copy_meta().unwrap())
                            .collect()
                    }
                }

                fn clear_src(&mut self) { self.src.clear() }
                fn clear_dst(&mut self) { self.dst.clear() }

                // Ideally this could be derived using getset but I don't seem
                // to find a way to do it in a trait

                fn dst(&self) -> &Vec<Option<VarCell>> { &self.dst }
                fn src(&self) -> &Vec<VarCell> { &self.src }
                fn uid(&self) -> &usize { &self.uid }
                fn load_stats(&self) -> &Option<LoadStats> { &self.load_stats }
                fn set_load_stats(&mut self, stats: LoadStats) { self.load_stats = Some(stats); }
                fn set_src(&mut self, src: Vec<VarCell>) { self.src = src; }
                fn dst_mut(&mut self) -> &mut Vec<Option<VarCell>> { &mut self.dst }
                fn unlinked(&self) -> Self {
                    let mut clone = self.clone();
                    clone.src.clear();
                    clone.dst.clear();
                    clone
                }
            }
        }
    }
}
