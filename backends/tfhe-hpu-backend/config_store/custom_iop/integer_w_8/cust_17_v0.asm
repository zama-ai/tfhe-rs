; Simple IOp to check PBS behavior
; Dest <- PBSNone(Src_a)
; ------------------------------------------------------------------------------
; !preamble {
; [signature]
; Ciphertext<8, 2, 2> -> Ciphertext<8, 2, 2>
; [lut]
; None: [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]
; } ----------------------------------------------------------------------------

LD    R0   TS[0].0
PBS   R0   R0    PbsNone
ST    TD[0].0 R0 
LD    R1   TS[0].1
PBS   R1   R1    PbsNone
ST    TD[0].1 R1 
LD    R2   TS[0].2
PBS   R2   R2    PbsNone
ST    TD[0].2 R2 
LD    R3   TS[0].3
PBS_F R3   R3    PbsNone
ST    TD[0].3 R3 
