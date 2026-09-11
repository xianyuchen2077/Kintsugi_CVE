<?php
class ComplexTestClass {
    private $data = array();

    public function __construct() {
        $this->initializeData();
    }

    private function initializeData() {
        $this->data = array(1, 2, 3, 4, 5);
    }

    public function processWithCallback($callback) {
        return $this->transformData($callback);
    }

    private function transformData($transformer) {
        $result = array();
        foreach ($this->data as $item) {
            $result[] = $transformer($item);
        }
        return $result;
    }

    public static function recursiveStaticMethod($n, $acc = 1) {
        if ($n <= 1) {
            return self::finalizeResult($acc);
        }
        return self::recursiveStaticMethod($n - 1, $acc * $n);
    }

    private static function finalizeResult($value) {
        return "Final result: " . $value;
    }
}

function globalHelperFunction($x) {
    return function($y) use ($x) {
        return $x * $y + nestedHelper($y);
    };
}

function nestedHelper($val) {
    if ($val > 3) {
        return recursiveHelper($val - 1);
    }
    return $val;
}

function recursiveHelper($n) {
    if ($n <= 1) return 1;
    return $n + recursiveHelper($n - 1);
}

echo "=== Test: Complex Mixed Scenarios ===\n";

$obj = new ComplexTestClass();

$dynamicCallback = globalHelperFunction(2);
$result1 = $obj->processWithCallback($dynamicCallback);
echo "Callback result: " . implode(", ", $result1) . "\n";

$result2 = ComplexTestClass::recursiveStaticMethod(5);
echo $result2 . "\n";

try {
    $complexResult = $obj->processWithCallback(function($x) {
        if ($x == 3) {
            throw new Exception("Special value exception");
        }
        return $x * 3;
    });
} catch (Exception $e) {
    echo "Caught exception: " . $e->getMessage() . "\n";
    $recovery = array_map(function($n) { return $n * 2; }, array(1, 2, 4, 5));
    echo "Recovery: " . implode(", ", $recovery) . "\n";
}
?>
