# An abstraction layer that can be use to analyze both mockup and hardware
# traces

import sys
import logging
from collections import defaultdict
from itertools import tee
from operator import attrgetter
from typing import Iterable, Iterator

import numpy as np
from pandas import DataFrame


def group_by_time(it, timef, threshold):
    try:
        batch = [next(it)]
        ptime = timef(batch[0])
        for obj, time in map(lambda i: (i, timef(i)), it):
            delta = time - ptime
            if (delta < threshold):
                batch.append(obj)
            else:
                yield batch
                batch = [obj]
            ptime = time
        if(len(batch)):
            yield batch
    except StopIteration:
        return

class BaseEvent:
    def as_dict(self):
        return {'event': self.__class__.__name__}

class InsnEvent:
    def as_dict(self):
        ret = BaseEvent.as_dict(self)
        ret.update({'insn': str(self.insn)})
        return ret

class Refill(InsnEvent):
    def __init__(self, insn):
        self.insn = insn

class Issue(InsnEvent):
    def __init__(self, insn):
        self.insn = insn

class Retire(InsnEvent):
    def __init__(self, insn):
        self.insn = insn

class RdUnlock(InsnEvent):
    def __init__(self, insn):
        self.insn = insn

class ReqTimeout(BaseEvent):
    def __init__(self, stamp):
        self.timestamp = stamp
    def as_dict(self):
        ret = super().as_dict()
        ret.update({'reset_time': self.timestamp})
        return ret

class Timeout(BaseEvent):
    def __init__(self):
        pass

class DelTimeout(BaseEvent):
    def __init__(self):
        pass

"""
A trace event
"""
class Event:
    def __init__(self, timestamp, data):
        self.timestamp = timestamp
        self.data = data

    def as_dict(self):
        ret = {'timestamp': self.timestamp}
        ret.update(self.data.as_dict())
        return ret

"""
A simplified instruction
"""
class Instruction:
    def __init__(self, opcode, args):
        self.opcode = opcode
        self.args = args

    def is_flush(self):
        return self.opcode.endswith("_F")

    def is_pbs(self):
        return self.opcode.startswith("PBS")

    def as_dict(self):
        return self.__dict__

    def __str__(self):
        return f"{self.opcode} {self.args}"

    def __hash__(self):
        return hash(str(self))

    def __eq__(self, other):
        return hash(self) == hash(other)

class Batch:
    def __init__(self, insns):
        self._insns = insns

    @property
    def latency(self):
        return self._insns[-1].latency

    def __len__(self):
        return len(self._insns)

    def __getitem__(self, k):
        return self._insns[k]

"""
Accumulator class for instruction latency
"""
class Latency:
    def __init__(self):
        self.acc = []
        self.data = set()

    def append(self, other, data):
        self.acc.append(other.latency)
        self.data.add(data)

    def as_dict(self):
        if len(self.acc):
            npa = np.array(list(filter(lambda x: x != np.NAN, self.acc)))
            return {"min": npa.min(), "avg": npa.mean(),
                    "max": npa.max(), "data": self.data, "count": len(npa)}
        else:
            return {"min": 'NA', "avg": 'NA',
                    "max": 'NA', "data": self.data, "count": 0}

class InstructionStats:
    def __init__(self, insn, latency, timestamp, delta, reltime):
        self.timestamp = timestamp
        self.latency = latency
        self.delta = delta
        self.reltime = reltime
        self.insn = insn

    def as_dict(self):
        ret = {
                'timestamp': self.timestamp,
                'latency': self.latency, 
                'delta': self.delta, 
                'reltime': self.reltime, 
                }
        ret.update(self.insn.as_dict())
        return ret

def peek(it: Iterable):
    ret, copy = tee(iter(it), 2)
    try:
        val = next(copy)
    except StopIteration:
        val = None
    return ret, val


"""
Iterable yielding Stats objects when iterated, results are not cached so don't
save the results if you want them more than once.
"""
class Retired:
    BATCH_THRESHOLD = 150000

    def __init__(self, trace: Iterable['Event']):
        self._events = list(self._filter(trace))

    @staticmethod
    def _filter(events: Iterable['Event']):
        isn_map = {}
        events, first = peek(events)
        if first is None:
            return
        first_stamp = prev_stamp = first.timestamp
        for event in filter(lambda x: x.data.__class__ in (Issue, Retire), events):
            insn = event.data.insn
            timestamp = event.timestamp
            if (event.data.__class__ == Retire):
                if insn in isn_map:
                    latency = timestamp - isn_map[insn]
                    del isn_map[insn]
                else:
                    latency = np.NAN
                delta = timestamp - prev_stamp
                reltime = timestamp - first_stamp 
                yield InstructionStats(insn, latency, timestamp, delta, reltime)
                prev_stamp = timestamp
            elif (event.data.__class__ == Issue):
                isn_map[insn] = timestamp

    def __iter__(self):
        return iter(self._events)

    def to_df(self):
        return DataFrame.from_records([x.as_dict() for x in self],
                                      index='timestamp')

    def runtime_us(self, freq_mhz) -> 'useconds':
        return (self._events[-1].timestamp - self._events[0].timestamp)/freq_mhz

    def pbs_batches(self, threshold = BATCH_THRESHOLD):
        pbs = filter(lambda i: i.insn.opcode.startswith('PBS'), self)
        return map(Batch, group_by_time(pbs, attrgetter('timestamp'), threshold))

    def pbs_latency_table(self, threshold = BATCH_THRESHOLD):
        pbs_latency_table = defaultdict(Latency, {})
        for batch in self.pbs_batches(threshold):
            pbs_latency_table[len(batch)].append(batch, batch[0].reltime)
        table = {i: x.as_dict() for i,x in pbs_latency_table.items()}
        return DataFrame.from_dict(table, orient="index").sort_index()

    def pbs_flushes(self):
        batch = []
        for insn in self:
            if insn.is_pbs():
                batch.append(insn)

            if insn.is_flush():
                yield Batch(batch)
                batch = []

        if len(batch):
                yield Batch(batch)


class Issued(Retired):
    @staticmethod
    def _filter(events: Iterable):
        events, first = peek(events)
        if first is None:
            return
        first_stamp = prev_stamp = first.timestamp
        for event in filter(lambda x: x.data.__class__ == Issue, events):
            insn = event.data.insn
            timestamp = event.timestamp
            if (event.data.__class__ == Issue):
                latency = None
                delta = timestamp - prev_stamp
                reltime = timestamp - first_stamp 
                yield InstructionStats(insn, latency, timestamp, delta, reltime)
                prev_stamp = timestamp


class Trace:
    def __init__(self, events: Iterable['Event']):
        self._events = list(events)

    def __iter__(self):
        return iter(self._events)

    def to_df(self):
        df = DataFrame.from_records([x.as_dict() for x in self],
                                      index='timestamp')
        df['reltime'] = df.index - df.index[0]
        return df
