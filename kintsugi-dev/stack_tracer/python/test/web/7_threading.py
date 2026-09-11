#!/usr/bin/env python3
"""Multi-threading call test"""
import threading
import time

def worker(thread_id):
    print("Thread {} started".format(thread_id))
    time.sleep(0.1)
    result = process_data(thread_id)
    print("Thread {} result: {}".format(thread_id, result))

def process_data(data):
    return data * 2

if __name__ == "__main__":
    print("=== Multi-Threading Call Test ===")

    threads = []
    for i in range(3):
        t = threading.Thread(target=worker, args=(i,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print("All threads completed")
