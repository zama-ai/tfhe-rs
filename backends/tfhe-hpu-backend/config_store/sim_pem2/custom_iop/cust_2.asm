# CUST_2
# Simple IOp to check PBS behavior
# Dest <- PBSNone(Src_a)
LD   R0   TA.0
PBS  R0   R0    PbsNone
ST   TD.0 R0 
LD   R1   TA.1
PBS  R1   R1    PbsNone
ST   TD.1 R1 
LD   R2   TA.2
PBS  R2   R2    PbsNone
ST   TD.2 R2 
LD   R3   TA.3
PBS  R3   R3    PbsNone
ST   TD.3 R3 
