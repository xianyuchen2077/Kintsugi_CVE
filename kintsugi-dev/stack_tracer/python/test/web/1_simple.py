#!/usr/bin/env python3
"""Simple function call test"""

def simple_function():
    return "Hello World"

def add_numbers(a, b):
    return a + b

if __name__ == "__main__":
    print("=== Simple Function Call Test ===")

    # Call function without args
    result1 = simple_function()
    print("Result1: {}".format(result1))

    # Call function with args
    result2 = add_numbers(10, 20)
    print("Result2: {}".format(result2))
