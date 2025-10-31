#!/usr/bin/env python3

from pandas import DataFrame
from isctrace.analysis import Refilled, Retired, Trace

freq_mhz = 400

iops = Trace.from_hw("data/trace.json")

def analyze_iop(iop):
    retired = Retired(iop)

    # Print the retired instructions as a table
    print(retired.to_df().to_string())

    # Print a batch latency table
    latency_table = retired.pbs_latency_table(freq_mhz=freq_mhz).drop(columns='data')
    print(latency_table)

    # And the runtime
    runtime = retired.runtime_us(freq_mhz=freq_mhz)
    print(f"batches: {latency_table['count'].sum()}")
    print(f"Runtime: {runtime}us")

if __name__ == "__main__":
    analyze_iop(iops[0])

# vim: fdm=marker
