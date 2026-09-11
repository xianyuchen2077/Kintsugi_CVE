#!/usr/bin/env python3
"""Nested function call test"""

def level_1():
    print("Level 1")
    return level_2()

def level_2():
    print("Level 2")
    return level_3()

def level_3():
    print("Level 3")
    return "Reached bottom"

if __name__ == "__main__":
    print("=== Nested Function Call Test ===")
    result = level_1()
    print("Result: {}".format(result))
