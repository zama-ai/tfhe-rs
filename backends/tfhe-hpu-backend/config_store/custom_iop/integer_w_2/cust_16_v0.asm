; Simple IOp to check PBS behavior
; Dest <- PBSNone(Src_a.0)
; ------------------------------------------------------------------------------
; !preamble {
; [signature]
; Ciphertext<2, 2, 2> -> Ciphertext<2, 2, 2>
; [lut]
; None: [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]
; } ----------------------------------------------------------------------------

LD     R0   TS[0].0
PBS_F  R0   R0    PbsNone
ST     TD[0].0 R0 
