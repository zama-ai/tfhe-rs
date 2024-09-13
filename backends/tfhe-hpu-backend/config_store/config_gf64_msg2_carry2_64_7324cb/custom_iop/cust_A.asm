# MUL              I4@[0]0xd92      I4@[0]0xc2a      I4@[0]0xa24     
LD               R0               TA.0            
LD               R1               TB.0            
MAC              R2               R0               R1               4               
LD               R3               TB.1            
MAC              R4               R0               R3               4               
LD               R5               TA.1            
MAC              R6               R5               R1               4               
PBS              R7               R2               PbsMultCarryMsgLsb
PBS              R8               R2               PbsMultCarryMsgMsb
PBS              R9               R4               PbsMultCarryMsgLsb
PBS              R10              R6               PbsMultCarryMsgLsb
ST               TD.0             R7              
ADD              R11              R8               R9              
ADD              R12              R11              R10             
PBS              R13              R12              PbsMsgOnly      
ST               TD.1             R13             
