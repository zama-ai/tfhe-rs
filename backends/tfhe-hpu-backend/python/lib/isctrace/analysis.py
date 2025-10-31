# An abstraction layer that can be use to analyze both mockup and hardware
# traces

import sys
import logging
from collections import defaultdict
from itertools import tee, chain, starmap
from operator import attrgetter, sub
from typing import Iterable, Iterator

import numpy as np
from pandas import DataFrame

def delta(a: Iterable[float]):
    a, b = tee(a, 2)
    b = chain(range(0,1), b)
    return starmap(sub, zip(a,b))

def group_by_time(it, timef, threshold):
    try:
        batch = [next(it)]
        ptime = timef(batch[0])
        for obj, time in map(lambda i: (i, timef(i)), it):
            delta = cmp_timestamp(time, ptime)
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
        ret.update({'data': f"{self.__dict__}"})
        return ret

class Timeout(BaseEvent):
    def __init__(self):
        pass

class DelTimeout(BaseEvent):
    def __init__(self):
        pass

class BatchStart(BaseEvent):
    def __init__(self, pe_id, issued):
        self.pe_id = pe_id
        self.issued = issued
    def as_dict(self):
        ret = super().as_dict()
        ret.update({'data': f"{self.__dict__}"})
        return ret

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
    def __init__(self, insns, latency = None):
        self._insns = insns
        self.latency = self._insns[-1].latency if latency is not None else latency

    def reltime(self):
        return max(map(lambda x: x.reltime, self._insns))

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
            npa = np.array(list(filter(lambda x: x != np.NAN, self.acc)),
                           dtype=float)
            return {"min": npa.min(), "avg": npa.mean(),
                    "max": npa.max(), "sum": npa.sum(),
                    "count": len(npa), "data": self.data}
        else:
            return {"min": 'NA', "avg": 'NA',
                    "max": 'NA', "sum": 'NA',
                    "count": 0, "data": self.data}

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
        if self.insn is not None:
            ret.update(self.insn.as_dict())
        return ret

def peek(it: Iterable):
    ret, copy = tee(iter(it), 2)
    try:
        val = next(copy)
    except StopIteration:
        val = None
    return ret, val

def cmp_timestamp(cur, last):
    return (cur - last)%2**32

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
                    latency = cmp_timestamp(timestamp, isn_map[insn])
                    del isn_map[insn]
                else:
                    latency = np.NAN
                delta = cmp_timestamp(timestamp, prev_stamp)
                reltime = cmp_timestamp(timestamp, first_stamp)
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
        return cmp_timestamp(self._events[-1].timestamp, self._events[0].timestamp)/freq_mhz

    def pbs_batches(self, threshold = BATCH_THRESHOLD):
        pbs = filter(lambda i: i.insn.opcode.startswith('PBS'), self)
        batches = list(map(Batch, group_by_time(pbs, attrgetter('timestamp'), threshold)))
        for batch, latency in zip(batches, delta(x.reltime() for x in batches)):
            batch.latency = latency
        return batches

    def pbs_latency_table(self, freq_mhz = 350, threshold = BATCH_THRESHOLD):
        pbs_latency_table = defaultdict(Latency, {})
        for batch in self.pbs_batches(threshold):
            pbs_latency_table[len(batch)].append(batch, batch[0].reltime)
        table = {i: x.as_dict() for i,x in pbs_latency_table.items()}
        df = DataFrame.from_dict(table, orient="index")
        clk_cols = ['min', 'avg', 'max', 'sum']
        df.loc[:, clk_cols] = df.loc[:, clk_cols].apply(lambda x: x/freq_mhz)
        df.index.name = 'batch size'
        return df.sort_index()

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
    match_class = Issue
    @classmethod
    def _filter(cls, events: Iterable):
        events, first = peek(events)
        if first is None:
            return
        first_stamp = prev_stamp = first.timestamp
        for event in filter(lambda x: x.data.__class__ == cls.match_class, events):
            insn = event.data.insn
            timestamp = event.timestamp
            if (event.data.__class__ == cls.match_class):
                latency = None
                delta = timestamp - prev_stamp
                reltime = timestamp - first_stamp 
                yield InstructionStats(insn, latency, timestamp, delta, reltime)
                prev_stamp = timestamp

class Refilled(Issued):
    match_class = Refill

class Trace:
    def __init__(self, events: Iterable['Event']):
        self._events = list(events)

    def __iter__(self):
        return iter(self._events)

    def __len__(self):
        return len(self._events)

    def to_df(self):
        df = DataFrame.from_records([x.as_dict() for x in self],
                                      index='timestamp')
        df['reltime'] = df.index - df.index[0]
        return df
