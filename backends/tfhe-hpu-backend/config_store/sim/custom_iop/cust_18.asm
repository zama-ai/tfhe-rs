; CUST_18
; Simple IOp to check extraction pattern
; Correct result:
;   * Dst[0,1] <- Src[0][0,1]
;   * Dst[2,3] <- Src[1][0,1]

; Pack Src[0][0,1] with a Mac and extract Carry/Msg in Dst[0][0,1]
LD R0 TS[0].0
LD R1 TS[0].1
MAC R3 R1 R0 4
PBS R4 R3 PbsMsgOnly
PBS R5 R3 PbsCarryInMsg
ST TD[0].0 R4 
ST TD[0].1 R5 

; Pack Src[1][0,1] with a Mac and extract Carry/Msg in Dst[0][2,3]
LD R10 TS[1].0
LD R11 TS[1].1
MAC R13 R11 R10 4
PBS R14 R13 PbsMsgOnly
PBS R15 R13 PbsCarryInMsg
ST TD[0].2 R14 
ST TD[0].3 R15 
