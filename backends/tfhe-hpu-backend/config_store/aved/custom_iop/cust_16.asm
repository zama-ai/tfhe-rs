# CUST_16
# Simple IOp to check PBS behavior
# Dest <- PBSNone(Src_a.0)
LD   R0   TS[0].0
PBS_F  R0   R0    PbsNone
ST   TD[0].0 R0 
