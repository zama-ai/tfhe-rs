; CUST_20
; Simple IOp to check PbsMl4
; Correct result:
;   * Dst[0][0]   <- Src[0][0]
;   * Dst[0][1]   <- Src[0][0] +1
;   * Dst[0][2]   <- Src[0][0] +2
;   * Dst[0][3]   <- Src[0][0] +3
; i.e Cust_20(0x0) => 0xe4 

SUB R16 R16 R16
ST TD[0].0 R0
ST TD[0].1 R0
ST TD[0].2 R0
ST TD[0].3 R0

; Apply PbsMl4 on Src[0] result goes in dest[0][0-3]
LD R0 TS[0].0
PBS_ML4_F R0 R0 PbsTestMany4
ST TD[0].0 R0
ST TD[0].1 R1
ST TD[0].2 R2
ST TD[0].3 R3
