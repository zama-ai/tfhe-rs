from . import analysis

class BaseInstruction:
    def __init__(self, data):
        self.data = data

    def args(self):
        return str(self.data)

    def __str__(self):
        return f'{self.__class__.__name__} {self.args()}'

class NamedInstruction:
    def __init__(self, name, args):
        self.name = name
        self._args = args
    def args(self):
        return self._args
    def __str__(self):
        return f'{self.name} {self.args()}'

class PBS(BaseInstruction):
    def __init__(self, d):
        self.__dict__ = d

    def args(self):
        return f'R{self.dst_rid} R{self.src_rid} @{self.gid}'

class LD(BaseInstruction):
    def __init__(self, d):
        self.__dict__ = d

    def args(self):
        try:
            return f'R{self.rid} @{hex(self.slot["Addr"])}'
        except:
            # It can happen that an IOP is not translated by the FW
            return f'R{self.rid} @{self.slot}'

class ST(BaseInstruction):
    def __init__(self, d):
        self.__dict__ = d

    def args(self):
        try:
            return f'@{hex(self.slot["Addr"])} R{self.rid}'
        except:
            # It can happen that an IOP is not translated by the FW
            return f'@{self.slot} R{self.rid}'

class MAC(BaseInstruction):
    def __init__(self, d):
        self.__dict__ = d

    def args(self):
        return f'R{self.dst_rid} R{self.src0_rid} ' +\
               f'R{self.src1_rid} X{self.mul_factor} '

class ADD(BaseInstruction):
    def __init__(self, d):
        self.__dict__ = d

    def args(self):
        return f'R{self.dst_rid} R{self.src0_rid} R{self.src1_rid}'

class ADDS(BaseInstruction):
    def __init__(self, d):
        self.__dict__ = d

    def args(self):
        return f'R{self.dst_rid} R{self.src_rid} {self.msg_cst["Cst"]}'

class SUB(BaseInstruction):
    def __init__(self, d):
        self.__dict__ = d

    def args(self):
        return f'R{self.dst_rid} R{self.src0_rid} R{self.src1_rid}'

class SSUB(BaseInstruction):
    def __init__(self, d):
        self.__dict__ = d

    def args(self):
        return f'R{self.dst_rid} {self.msg_cst["Cst"]} R{self.src_rid}'

class SUBS(BaseInstruction):
    def __init__(self, d):
        self.__dict__ = d

    def args(self):
        return f'R{self.dst_rid} R{self.src_rid} {self.msg_cst["Cst"]}'

class SYNC(BaseInstruction):
    def __init__(self, d):
        self.__dict__ = d

    def args(self):
        return f"{self.sid}"

PBS_ML2   = PBS
PBS_ML4   = PBS
PBS_ML8   = PBS
PBS_F     = PBS
PBS_ML2_F = PBS
PBS_ML4_F = PBS
PBS_ML8_F = PBS
MULS      = ADDS
SUBS      = ADDS

class Insn:
    def __init__(self, insn):
        self.opcode, data = next(iter(insn.items()))
        self.data = globals()[self.opcode](data) if self.opcode in globals() \
                    else NamedInstruction(self.opcode, data)

    def to_analysis(self):
        return analysis.Instruction(self.opcode, self.data.args())
