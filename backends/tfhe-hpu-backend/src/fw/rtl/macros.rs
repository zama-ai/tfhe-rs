#[macro_export]
macro_rules! rtl_op {
    (
        $name: literal,
        $kind: ident,
        $data: ty
    ) => {
        ::paste::paste! {
            #[derive(Clone)]
            pub struct [<$name:camel Op>] {
                src: Vec<VarCell>,
                dst: Vec<Option<VarCell>>,
                uid: usize,
                load_stats: Option<LoadStats>,
                data: $data,
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
                fn clone_on(&self, prog: &Program) -> Operation {
                    Operation::[<$name:upper>](Self {
                        src: self.src.iter().map(|v| v.clone_on(prog)).collect(),
                        dst: self.dst.iter().map(|_| None).collect(),
                        uid: self.uid,
                        load_stats: self.load_stats.clone(),
                        data: self.data.clone(),
                    })
                }

                #[cfg(feature = "rtl_graph")]
                fn name(&self) -> &str {
                    $name
                }
                fn kind(&self) -> InstructionKind {
                    InstructionKind::$kind
                }

                fn clear_src(&mut self) { self.src.clear() }
                fn clear_dst(&mut self) { self.dst.clear() }

                // Ideally this could be derived using getset but I don't seem
                // to find a way to do it in a trait

                fn dst(&self) -> &Vec<Option<VarCell>> { &self.dst }
                fn src(&self) -> &Vec<VarCell> { &self.src }
                fn uid(&self) -> &usize { &self.uid }
                fn load_stats(&self) -> &Option<LoadStats> { &self.load_stats }
                fn load_stats_mut(&mut self) -> &mut Option<LoadStats> { &mut self.load_stats }
                fn dst_mut(&mut self) -> &mut Vec<Option<VarCell>> { &mut self.dst }
            }

            impl Debug for [<$name:camel Op>] {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
                    f.debug_struct($name)
                        .field("uid", self.uid())
                        .field("dst", &self.dst().len())
                        .field("data", &self.data)
                        .finish()
                }
            }
        }
    };
}
