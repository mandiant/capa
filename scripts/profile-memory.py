# Copyright (C) 2021 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import gc
import linecache
import tracemalloc

tracemalloc.start()


def display_top(snapshot, key_type="lineno", limit=10):
    # via: https://docs.python.org/3/library/tracemalloc.html#pretty-top
    snapshot = snapshot.filter_traces(
        (
            tracemalloc.Filter(False, "<frozen importlib._bootstrap_external>"),
            tracemalloc.Filter(False, "<frozen importlib._bootstrap>"),
            tracemalloc.Filter(False, "<unknown>"),
        )
    )
    top_stats = snapshot.statistics(key_type)

    print(f"Top {limit} lines")
    for index, stat in enumerate(top_stats[:limit], 1):
        frame = stat.traceback[0]
        print(f"#{index}: {frame.filename}:{frame.lineno}: {(stat.size/1024):.1f} KiB")
        line = linecache.getline(frame.filename, frame.lineno).strip()
        if line:
            print(f"    {line}")

    other = top_stats[limit:]
    if other:
        size = sum(stat.size for stat in other)
        print(f"{len(other)} other: {(size/1024):.1f} KiB")
    total = sum(stat.size for stat in top_stats)
    print(f"Total allocated size: {(total/1024):.1f} KiB")


def main():
    # import within main to keep isort happy
    # while also invoking tracemalloc.start() immediately upon start.
    import io
    import os
    import time
    import contextlib

    import psutil

    import capa.main

    count = int(os.environ.get("CAPA_PROFILE_COUNT", 1))
    print(f"total iterations planned: {count} (set via env var CAPA_PROFILE_COUNT).")
    print()

    for i in range(count):
        print(f"iteration {i+1}/{count}...")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            t0 = time.time()
            capa.main.main()
            t1 = time.time()

            gc.collect()

        process = psutil.Process(os.getpid())
        print(f"  duration: {(t1-t0):.2f}")
        print(f"  rss: {(process.memory_info().rss / 1024 / 1024):.1f} MiB")
        print(f"  vms: {(process.memory_info().vms / 1024 / 1024):.1f} MiB")

    print("done.")
    gc.collect()

    snapshot0 = tracemalloc.take_snapshot()
    display_top(snapshot0)


main()
