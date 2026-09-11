#!/usr/bin/env python3
"""Class method call test"""

class Calculator:
    def __init__(self, name):
        self.name = name

    def add(self, a, b):
        return a + b

    def multiply(self, a, b):
        return self._internal_multiply(a, b)

    def _internal_multiply(self, a, b):
        return a * b

if __name__ == "__main__":
    print("=== Class Method Call Test ===")

    calc = Calculator("MyCalc")
    result1 = calc.add(5, 3)
    print("5 + 3 = {}".format(result1))

    result2 = calc.multiply(4, 7)
    print("4 * 7 = {}".format(result2))
