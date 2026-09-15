; IOp to debug multi-hpu data xfer and sync
; This IOp take two sources and generate two destination (one written by each node)
; Focus on LD templated Op from other Hpu
; HPU0 construct B[1]B[0]A[1]A[0]
; HPU1 construct B[3]B[2]A[3]A[2]
; ------------------------------------------------------------------------------
; !preamble {
; [signature]
; (Ciphertext<8, 2, 2>, Ciphertext<8, 2, 2>) -> (Ciphertext<8, 2, 2>, Ciphertext<8, 2, 2>)
; [lut]
; None: [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]
; } ----------------------------------------------------------------------------

LD_B2B F1 TH.0

LD_B2B F0 TS[0].2
LD_B2B F0 TS[0].3
LD_B2B F0 TS[1].2
LD_B2B F0 TS[1].3

LD R0 TS[0].2
LD R1 TS[0].3
LD R2 TS[1].2
LD R3 TS[1].3

PBS R0 R0 PbsNone
PBS R1 R1 PbsNone
PBS R2 R2 PbsNone
PBS_F R3 R3 PbsNone
PBS R0 R0 PbsNone
PBS R1 R1 PbsNone
PBS R2 R2 PbsNone
PBS_F R3 R3 PbsNone
PBS R0 R0 PbsNone
PBS R1 R1 PbsNone
PBS R2 R2 PbsNone
PBS_F R3 R3 PbsNone

WAIT F1 TH.0
LD R4 TH.0
PBS_F R4 R4 PbsNone

ST TD[1].0 R0 
ST TD[1].1 R1 
ST TD[1].2 R2 
ST TD[1].3 R3 
