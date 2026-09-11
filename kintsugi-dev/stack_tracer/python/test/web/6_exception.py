#!/usr/bin/env python3
"""Exception handling test"""

def divide(a, b):
    try:
        return safe_divide(a, b)
    except ZeroDivisionError:
        return "Error: Division by zero"

def safe_divide(x, y):
    return x / y

if __name__ == "__main__":
    print("=== Exception Handling Test ===")

    # Normal division
    result1 = divide(10, 2)
    print("10 / 2 = {}".format(result1))

    # Division by zero
    result2 = divide(10, 0)
    print("10 / 0 = {}".format(result2))
