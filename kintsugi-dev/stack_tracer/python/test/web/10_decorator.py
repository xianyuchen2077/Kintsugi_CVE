#!/usr/bin/env python3
"""Decorator test"""

def log_call(func):
    """Simple logging decorator"""
    def wrapper(*args, **kwargs):
        print("Calling {}".format(func.__name__))
        result = func(*args, **kwargs)
        print("{} returned {}".format(func.__name__, result))
        return result
    return wrapper

@log_call
def add(a, b):
    return a + b

@log_call
def multiply(a, b):
    return a * b

if __name__ == "__main__":
    print("=== Decorator Test ===")

    result1 = add(3, 4)
    print("3 + 4 = {}\n".format(result1))

    result2 = multiply(5, 6)
    print("5 * 6 = {}".format(result2))
