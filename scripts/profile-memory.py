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

    print("Top %s lines" % limit)
    for index, stat in enumerate(top_stats[:limit], 1):
        frame = stat.traceback[0]
        print("#%s: %s:%s: %.1f KiB" % (index, frame.filename, frame.lineno, stat.size / 1024))
        line = linecache.getline(frame.filename, frame.lineno).strip()
        if line:
            print("    %s" % line)

    other = top_stats[limit:]
    if other:
        size = sum(stat.size for stat in other)
        print("%s other: %.1f KiB" % (len(other), size / 1024))
    total = sum(stat.size for stat in top_stats)
    print("Total allocated size: %.1f KiB" % (total / 1024))


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
    print("total iterations planned: %d (set via env var CAPA_PROFILE_COUNT)." % (count))
    print()

    for i in range(count):
        print("iteration %d/%d..." % (i + 1, count))
        with contextlib.redirect_stdout(io.StringIO()):
            with contextlib.redirect_stderr(io.StringIO()):
                t0 = time.time()
                capa.main.main()
                t1 = time.time()

                gc.collect()

        process = psutil.Process(os.getpid())
        print("  duration: %0.02fs" % (t1 - t0))
        print("  rss: %.1f MiB" % (process.memory_info().rss / 1024 / 1024))
        print("  vms: %.1f MiB" % (process.memory_info().vms / 1024 / 1024))

    print("done.")
    gc.collect()

    snapshot0 = tracemalloc.take_snapshot()
    display_top(snapshot0)


main()
