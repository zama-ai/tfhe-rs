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
    def __init__(self, d, asm):
        self.__dict__ = d
        self.asm = asm

    def args(self):
        return f'{self.asm.partition(" ")[2]}'

class LD(BaseInstruction):
    def __init__(self, d, asm):
        self.__dict__ = d

    def args(self):
        try:
            return f'R{self.dst["addr"]} @{hex(self.src["Io"]["addr"])}'
        except:
            # It can happen that an IOP is not translated by the FW
            return f'R{self.dst} @{self.src}'

class ST(BaseInstruction):
    def __init__(self, d, asm):
        self.__dict__ = d

    def args(self):
        try:
            return f'@{hex(self.dst["Io"]["addr"])} R{self.src["addr"]}'
        except:
            # It can happen that an IOP is not translated by the FW
            return f'@{self.dst} R{self.src}'

class MAC(BaseInstruction):
    def __init__(self, d, asm):
        self.__dict__ = d

    def args(self):
        return f'R{self.dst["addr"]} R{self.src1["addr"]} ' +\
               f'R{self.src2["addr"]} x{self.cst["Const"]["val"]} '

class ADD(BaseInstruction):
    def __init__(self, d, asm):
        self.__dict__ = d

    def args(self):
        return f'R{self.dst["addr"]} R{self.src1["addr"]} R{self.src2["addr"]}'

class ADDS(BaseInstruction):
    def __init__(self, d, asm):
        self.__dict__ = d

    def args(self):
        return f'R{self.dst["addr"]} R{self.src["addr"]} {self.cst["Const"]["val"]}'

class SUB(BaseInstruction):
    def __init__(self, d, asm):
        self.__dict__ = d

    def args(self):
        return f'R{self.dst["addr"]} R{self.src1["addr"]} R{self.src2["addr"]}'

class SSUB(BaseInstruction):
    def __init__(self, d, asm):
        self.__dict__ = d

    def args(self):
        return f'R{self.dst["addr"]} {self.cst["Const"]["val"]} R{self.src["addr"]}'

class SUBS(BaseInstruction):
    def __init__(self, d, asm):
        self.__dict__ = d

    def args(self):
        return f'R{self.dst["addr"]} R{self.src["addr"]} {self.cst["Const"]["val"]}'

class SYNC(BaseInstruction):
    def __init__(self, d, asm):
        self.__dict__ = d

    def args(self):
        return f"{self.iid} {self.is_inner}"

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
    def __init__(self, insn, asm):
        self.opcode, data = next(iter(insn.items()))
        self.data = globals()[self.opcode](data, asm) if self.opcode in globals() \
                    else NamedInstruction(self.opcode, data, asm)

    def to_analysis(self):
        return analysis.Instruction(self.opcode, self.data.args())
