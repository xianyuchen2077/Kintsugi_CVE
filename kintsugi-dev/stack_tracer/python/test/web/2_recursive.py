#!/usr/bin/env python3
"""Recursive function call test"""

def factorial(n):
    if n <= 1:
        return 1
    return n * factorial(n - 1)

def fibonacci(n):
    if n <= 1:
        return n
    return fibonacci(n - 1) + fibonacci(n - 2)

if __name__ == "__main__":
    print("=== Recursive Function Call Test ===")

    # Factorial test
    fact = factorial(5)
    print("factorial(5): {}".format(fact))

    # Fibonacci test
    fib = fibonacci(6)
    print("fibonacci(6): {}".format(fib))
