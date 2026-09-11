#!/usr/bin/env python3
"""Module import and call test"""
import os
import json

def use_builtin_modules():
    # Use os module
    cwd = os.getcwd()
    print("Current dir: {}".format(cwd))

    # Use json module
    data = {"name": "test", "value": 123}
    json_str = json.dumps(data)
    print("JSON: {}".format(json_str))

    return True

if __name__ == "__main__":
    print("=== Module Import And Call Test ===")
    result = use_builtin_modules()
    print("Result: {}".format(result))
