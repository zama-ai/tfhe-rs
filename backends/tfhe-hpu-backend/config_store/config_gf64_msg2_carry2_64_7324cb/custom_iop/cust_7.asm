# CUST_7
# Simple IOp to check common pattern behavior
# Dest <- PBSNone(Src_a)
LD   R0   TA.0
LD   R1   TB.0
MAC  R2   R1 R0 4
PBS  R0   R2    PbsNone
ST   TD.0 R0 
