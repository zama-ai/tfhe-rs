# A Library to load mockup traces
import json

import pandas

from . import analysis, fmt


class ArgId:
    def __init__(self, d):
        self.__dict__ = d

class Instruction:
    def __init__(self, d):
        self.__dict__.update(d)
        self.dst_id = ArgId(self.dst_id)
        self.srca_id = ArgId(self.srca_id)
        self.srcb_id = ArgId(self.srcb_id)
        self.insn = fmt.Insn(d['op'])

    def __str__(self):
        return str(self.insn)

class Slot:
    def __init__(self, d):
        self.insn_data = Instruction(d['inst'])
        self.state = d['state']

    def __str__(self):
        return str(self.insn_data)

    def to_analysis(self):
        return self.insn_data.insn.to_analysis()

# The only two subtypes
class Query:
    def __init__(self, event):
        self.__dict__.update(event)
        self.slot = Slot(self.slot)
        self.subtype = self.cmd
        self.desc = str(self.slot)
    def to_analysis(self):
        return getattr(analysis, self.subtype)(self.slot.to_analysis())

class ReqTimeout:
    def __init__(self, timestamp):
        self.timestamp = timestamp
    def to_analysis(self):
        return analysis.ReqTimeout(self.timestamp)

class BatchStart:
    def __init__(self, d):
        self.pe_id = d['pe_id']
        self.issued = d['issued']
    def to_analysis(self):
        return analysis.BatchStart(self.pe_id, self.issued)

class NamedEvent:
    def __init__(self, name):
        self.name = name
    def to_analysis(self):
        return getattr(analysis, self.name)()

class Event:
    def __init__(self, trace_dict):
        self.timestamp = trace_dict['timestamp']
        event = trace_dict['event']

        if event.__class__ == dict:
            key = next(iter(event.keys()))
            self.event = globals()[key](event[key])
        else:
            self.event = NamedEvent(event)

    def to_analysis(self):
        return analysis.Event(
                timestamp=self.timestamp,
                data=self.event.to_analysis())

class Trace:
    def __init__(self, jsonfile):
        with open(jsonfile, 'r') as fd:
            self.traces = list(map(Event, json.load(fd)))
    def __iter__(self):
        return iter(self.traces)
    def to_analysis(self):
        return analysis.Trace((x.to_analysis() for x in self))

def from_mockup(filename: str) -> 'analysis.Trace':
    return Trace(filename).to_analysis()

# Register a from directly in analysis code
setattr(analysis.Trace, 'from_mockup', from_mockup)
