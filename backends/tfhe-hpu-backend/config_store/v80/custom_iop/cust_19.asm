; CUST_19
; Simple IOp to check PbsMl2
; Correct result:
;   * Dst[0][0]   <- Src[0][0]
;   * Dst[0][1]   <- 0
;   * Dst[0][2]   <- Src[0][0] +1
;   * Dst[0][3]   <- 0
; i.e Cust_19(0x2) => 0x32 

; Construct a 0 for destination padding
SUB R16 R16 R16

; Apply PbsMl2 on Src[0] result goes in dest[0][0-3] (0-padded)
LD R0 TS[0].0
PBS_ML2_F R0 R0 PbsTestMany2
ST TD[0].0 R0 
ST TD[0].1 R16
ST TD[0].2 R1 
ST TD[0].3 R16
