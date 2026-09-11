#!/usr/bin/env python3
"""Function call with args test"""

def process_string(text, prefix="", suffix=""):
    return "{}{}{}".format(prefix, text, suffix)

def calculate(x, y, operation="add"):
    if operation == "add":
        return x + y
    elif operation == "multiply":
        return x * y
    elif operation == "subtract":
        return x - y
    else:
        return 0

if __name__ == "__main__":
    print("=== Function Call With Args Test ===")

    # String processing
    result1 = process_string("Hello", prefix=">>", suffix="<<")
    print("Result1: {}".format(result1))

    # Calculate with default args
    result2 = calculate(10, 5, operation="add")
    print("10 + 5 = {}".format(result2))

    result3 = calculate(10, 5, operation="multiply")
    print("10 * 5 = {}".format(result3))
