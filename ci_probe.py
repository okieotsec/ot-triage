"""TEMPORARY diagnostic for the CI hang: runs the tests and, if they stall, prints which widgets keep resizing."""
import collections
import os
import sys
import threading
import time
import tkinter
import unittest

seq, total, sizes, info = [], collections.Counter(), collections.defaultdict(set), {}
original_init = tkinter.Tk.__init__


def patched_init(self, *args, **kwargs):
    original_init(self, *args, **kwargs)

    def seen(event):
        key = str(event.widget)
        total[key] += 1
        sizes[key].add((event.width, event.height))
        info[key] = event.widget.winfo_class()
        if len(seq) < 20000:
            seq.append((key, event.width, event.height))
    self.bind_all("<Configure>", seen, add="+")


tkinter.Tk.__init__ = patched_init


def watchdog(seconds, label):
    time.sleep(seconds)
    print(f"\n=== STALL after {seconds}s while running: {label}")
    busy = [k for k in total if len(sizes[k]) >= 2 and total[k] > 300]
    print("widgets that keep changing size:", len(busy))
    for key in sorted(busy, key=lambda k: -total[k])[:12]:
        print(f"  {total[key]:>6}x {info[key]:<12} {key[-60:]} sizes={sorted(sizes[key])[:4]}")
    print("last 12 events:")
    for key, width, height in seq[-12:]:
        print(f"  {key[-50:]:<50} {width}x{height}")
    sys.stdout.flush()
    os._exit(3)


if __name__ == "__main__":
    pattern, seconds = sys.argv[1], int(sys.argv[2])
    threading.Thread(target=watchdog, args=(seconds, pattern), daemon=True).start()
    unittest.main(module=None, argv=["unittest", "discover", "-v", "-p", pattern])
