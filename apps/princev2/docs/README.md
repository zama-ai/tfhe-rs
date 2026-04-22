# PRINCEv2 round diagrams

Each script in this directory is standalone (Python 3, no dependencies) and writes one SVG next
to itself. The SVGs are not checked in; generate them on demand:

```bash
cd apps/princev2/docs
python3 gen_fw_round_diagram.py       # -> princev2_fw_round.svg
python3 gen_bw_round_diagram.py       # -> princev2_bw_round.svg
python3 gen_fhe_fw_round_diagram.py   # -> princev2_fhe_fw_round.svg
python3 gen_fhe_bw_round_diagram.py   # -> princev2_fhe_bw_round.svg
```

Every script re-derives its wiring from constants copied out of `../src/tables.rs` and asserts
the derivation on the way. The cipher-level scripts check that their permutations are bijections
and replay the FHE dataflow — packed bit-plane u4s, `u4_exor` through the gather, then the folds
— against the M̂ edges they draw. The FHE scripts additionally check that the layers they draw
separately recompose into the fused permutations the code applies, and compute the PBS and
ciphertext-add totals shown in their legends rather than stating them. A script that exits
non-zero means the diagram no longer describes the source.

## The two levels

The diagrams come in pairs, one per direction, at two different levels of abstraction.

**Cipher level** — `gen_fw_round_diagram.py`, `gen_bw_round_diagram.py`. PRINCEv2 as specified in
[BEK+20]: 64 individually drawn bit wires through `⊕k`, `⊕RC`, `SubCells`, `M̂`, `ShiftRows`, one
layer per stage. This is *not* the shape the code evaluates — round constants are folded into the
S-box LUTs and ShiftRows is fused into the M-layer gather — so read these for the cipher, not for
the implementation.

**FHE level** — `gen_fhe_fw_round_diagram.py`, `gen_fhe_bw_round_diagram.py`. The dataflow
`src/cipher.rs` actually evaluates, one diagram per `xor_then_fw_round` / `xor_then_bw_round`
call: each shortint ciphertext is a wire whose thickness encodes how many state bits it packs
(`bits` / `u2h` / `u2l` / `u4`, the formats listed at the top of `cipher.rs`), every
`unchecked_add` is a `(+)` node, and every `apply_lookup_table` is a coloured box costing one PBS.
The key ciphertexts arrive in `u2l` and the state is in `u2h`, so the key add packs the two into
one nibble and the LUT that follows is what actually xors them. Each carries a
per-round PBS and ciphertext-add count in its legend. Every stage annotation names the
`cipher.rs` function or the `tables.rs` lookup table it stands for, so a stage can be grepped
straight back to the source. Where the code fuses a permutation into a gather, the diagram
unfuses it into a separate wiring stage so it can be read against the cipher-level diagram; the
assertions at the top of each script pin that equivalence.

The backward diagrams are drawn bottom-to-top, so placing one beside the matching forward diagram
shows the two undoing each other layer by layer.

There is deliberately no diagram for `xor_then_mid_round`. Nor for the two stages that sit
outside any round: the `unchecked_scalar_mul(_, 4)` that lifts the input to `u2h`, and the
closing `xor_to_u2l`.
