import json
from collections import defaultdict
from itertools import accumulate, chain, islice, tee
from operator import attrgetter
from typing import Iterator
import logging

import numpy as np
from pandas import DataFrame

from . import analysis, fmt

"""
A trace event
"""
class Event:
    EVENT_MAP = {
        "ISSUE": lambda x: analysis.Issue(fmt.Insn(x.insn).to_analysis()),
        "RETIRE": lambda x: analysis.Retire(fmt.Insn(x.insn).to_analysis()),
        "RDUNLOCK": lambda x: analysis.RdUnlock(fmt.Insn(x.insn).to_analysis()),
        "REFILL": lambda x: analysis.Refill(None),
    }

    def __init__(self, trace_dict):
        self.cmd = trace_dict['cmd']
        self.insn_asm = trace_dict['insn_asm']
        self.timestamp = trace_dict['timestamp']
        self.insn = trace_dict['insn']
        self.sync_id = trace_dict['state']['sync_id']

    def as_dict(self):
        return self.__dict__

    @staticmethod
    def default():
        return Event({"cmd": "NONE", "insn_asm": "", "timestamp": 0})

    def to_analysis(self) -> 'analysis.Event':
        return analysis.Event(
            timestamp=self.timestamp,
            data=self.EVENT_MAP[self.cmd](self))


"""
A collection of hardware events
"""
class Trace:
    def __init__(self, events):
        self._events = events

    @staticmethod
    def from_json(filename):
        with open(filename, 'r') as fd: 
            return Trace([Event(x) for x in json.load(fd)])

    def __iter__(self):
        return iter(self._events)

    def __len__(self):
        return len(self._events)

    # Tries to split the event stream in IOP boundaries
    def iops(self):
        id_map = defaultdict(list, {})
        for event in self:
            id_map[event.sync_id].append(event)
            opcode = next(iter(event.insn.keys())) if event.insn is not None else None

            if opcode == "SYNC":
                yield Trace(id_map[event.sync_id])
                del id_map[event.sync_id]

        if len(id_map):
            logging.warning("The trace contains incomplete IOPs")

    def to_analysis(self) -> Iterator['analysis.Event']:
        return analysis.Trace(x.to_analysis() for x in self)

def from_hw(filename) -> 'analysis.Trace':
    return [x.to_analysis() for x in Trace.from_json(filename).iops()]

# Register a factory function directly in the analysis module
setattr(analysis.Trace, 'from_hw', from_hw)
