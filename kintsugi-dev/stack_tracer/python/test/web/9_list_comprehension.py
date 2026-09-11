#!/usr/bin/env python3
"""List comprehension and higher-order function test"""

def process_list(numbers):
    # List comprehension
    squared = [x**2 for x in numbers]
    return squared

def filter_even(numbers):
    return list(filter(lambda x: x % 2 == 0, numbers))

def map_double(numbers):
    return list(map(lambda x: x * 2, numbers))

if __name__ == "__main__":
    print("=== List Comprehension Test ===")

    numbers = [1, 2, 3, 4, 5]

    # Squared
    result1 = process_list(numbers)
    print("Squared: {}".format(result1))

    # Filter even
    result2 = filter_even(numbers)
    print("Even: {}".format(result2))

    # Map double
    result3 = map_double(numbers)
    print("Doubled: {}".format(result3))
