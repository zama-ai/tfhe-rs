import json
from pandas import DataFrame


class Instruction:
    def __init__(self, asm, duration, timestamp):
        self.asm = asm
        self.duration = duration
        self.timestamp = timestamp

    def __repr__(self):
        return f"{self.name} {self.duration} {self.timestamp}"

    def as_dict(self):
        return self.__dict__


class Event:
    def __init__(self, trace_dict):
        self.__dict__.update(
                {x: trace_dict[x] for x in ("cmd", "insn_asm", "timestamp")})

    def as_dict(self):
        return self.__dict__


class Trace:
    def __init__(self, filename):
        with open(filename, 'r') as fd: 
            self.events = [Event(x) for x in json.load(fd)]

    def __iter__(self):
        return iter(self.events)

    def to_pandas(self):
        return DataFrame.from_records([x.as_dict() for x in self],
        index='timestamp')

    def instructions(self):
        isn_map = {}
        for event in filter(lambda x: x.cmd in ("ISSUE", "RETIRE"), self):
            asm = event.insn_asm
            if (event.cmd == "RETIRE" and asm in isn_map):
                yield Instruction(asm, event.timestamp - isn_map[asm],
                                  event.timestamp)
                del isn_map[asm]
            elif (event.cmd == "ISSUE"):
                isn_map[asm] = event.timestamp

    def to_pandas_delta(self):
        return DataFrame.from_records([x.as_dict() for x in self.instructions()])


if __name__ == "__main__":
    trace = Trace("example.json")
    df = trace.to_pandas()
    df = df[df.cmd == "RETIRE"]
    print(df.to_string())
    print(trace.to_pandas_delta().to_string())

