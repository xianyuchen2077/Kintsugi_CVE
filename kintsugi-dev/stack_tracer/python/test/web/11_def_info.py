#!/usr/bin/env python3
"""Function definition info test - test four cases of getting func_obj"""

import subprocess
import json


# ============================================================================
# Case 3: Current module global function
# ============================================================================
def global_function(x, y):
    """Module-level global function"""
    return x + y


def another_global_function():
    """Another global function that calls other global functions"""
    result = global_function(10, 20)
    return result


# ============================================================================
# Case 1: Instance method self.method()
# ============================================================================
class InstanceMethodClass:
    """Test instance method class"""

    def __init__(self, name):
        self.name = name

    def instance_method(self, value):
        """Instance method"""
        return "{}: {}".format(self.name, value)

    def call_another_instance_method(self):
        """Call another instance method"""
        return self.instance_method("hello")


# ============================================================================
# Case 2: Class method cls.method()
# ============================================================================
class ClassMethodClass:
    """Test class method class"""
    counter = 0

    @classmethod
    def class_method(cls, increment):
        """Class method"""
        cls.counter += increment
        return cls.counter

    @classmethod
    def call_another_class_method(cls):
        """Call another class method"""
        return cls.class_method(5)

    @classmethod
    def get_class_name(cls):
        """Return class name"""
        return cls.__name__


# ============================================================================
# Case 4: Module-level function (e.g. subprocess.getoutput)
# ============================================================================
def use_module_function():
    """Call standard library module function"""
    # Use subprocess.getoutput - typical example of case 4
    result = subprocess.getoutput("echo hello")
    return result


def use_json_module():
    """Call json module function"""
    data = {"key": "value"}
    # json.dumps is a module-level function
    json_str = json.dumps(data)
    return json_str


# ============================================================================
# Mixed test
# ============================================================================
class MixedTestClass:
    """Mixed test class - contains both instance and class methods"""

    shared_value = 100

    def __init__(self, value):
        self.value = value

    def instance_add(self, x):
        """Instance method calling global function"""
        return global_function(self.value, x)

    @classmethod
    def class_multiply(cls, factor):
        """Class method using shared value"""
        cls.shared_value *= factor
        return cls.shared_value

    def call_module_from_instance(self):
        """Instance method calling module function"""
        return json.dumps({"instance_value": self.value})

    @classmethod
    def call_module_from_classmethod(cls):
        """Class method calling module function"""
        return json.dumps({"shared_value": cls.shared_value})


if __name__ == "__main__":
    print("=== Function Definition Info Test ===\n")

    # --- Test case 3: Global function ---
    print("--- Case 3: Global Function Test ---")
    result = global_function(1, 2)
    print("global_function(1, 2) = {}".format(result))

    result = another_global_function()
    print("another_global_function() = {}".format(result))

    # --- Test case 1: Instance method ---
    print("\n--- Case 1: Instance Method Test ---")
    obj = InstanceMethodClass("TestInstance")
    result = obj.instance_method("world")
    print("obj.instance_method('world') = {}".format(result))

    result = obj.call_another_instance_method()
    print("obj.call_another_instance_method() = {}".format(result))

    # --- Test case 2: Class method ---
    print("\n--- Case 2: Class Method Test ---")
    result = ClassMethodClass.class_method(10)
    print("ClassMethodClass.class_method(10) = {}".format(result))

    result = ClassMethodClass.call_another_class_method()
    print("ClassMethodClass.call_another_class_method() = {}".format(result))

    result = ClassMethodClass.get_class_name()
    print("ClassMethodClass.get_class_name() = {}".format(result))

    # --- Test case 4: Module-level function ---
    print("\n--- Case 4: Module-Level Function Test ---")
    result = use_module_function()
    print("use_module_function() = {}".format(result))

    result = use_json_module()
    print("use_json_module() = {}".format(result))

    # --- Mixed test ---
    print("\n--- Mixed Test ---")
    mixed = MixedTestClass(50)

    result = mixed.instance_add(25)
    print("mixed.instance_add(25) = {}".format(result))

    result = MixedTestClass.class_multiply(2)
    print("MixedTestClass.class_multiply(2) = {}".format(result))

    result = mixed.call_module_from_instance()
    print("mixed.call_module_from_instance() = {}".format(result))

    result = MixedTestClass.call_module_from_classmethod()
    print("MixedTestClass.call_module_from_classmethod() = {}".format(result))

    print("\n=== Test Completed ===")
