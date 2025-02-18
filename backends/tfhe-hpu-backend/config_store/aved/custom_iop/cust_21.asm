; CUST_21
; Simple IOp to check PbsMl8
; WARN: This operation required 16b ct width
; Correct result:
;   * Dst[0][0]   <- Src[0][0]
;   * Dst[0][1]   <- Src[0][0] +1
;   * Dst[0][2]   <- Src[0][0] +2
;   * Dst[0][3]   <- Src[0][0] +3
;   * Dst[0][4]   <- Src[0][0] +4
;   * Dst[0][5]   <- Src[0][0] +5
;   * Dst[0][6]   <- Src[0][0] +6
;   * Dst[0][7]   <- Src[0][0] +7

; Apply PbsMl8 on Src[0] result goes in dest[0][0-7]
LD R0 TS[0].0
PBS_ML8_F R0 R0 PbsTestMany8
ST TD[0].0 R0
ST TD[0].1 R1
ST TD[0].2 R2
ST TD[0].3 R3
ST TD[0].4 R4
ST TD[0].5 R5
ST TD[0].6 R6
ST TD[0].7 R7
