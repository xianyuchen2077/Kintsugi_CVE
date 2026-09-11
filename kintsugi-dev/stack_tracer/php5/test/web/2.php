<?php
function factorial($n) {
    if ($n <= 1) {
        return 1;
    }
    return $n * factorial($n - 1);
}

function fibonacci($n) {
    if ($n <= 1) {
        return $n;
    }
    return fibonacci($n - 1) + fibonacci($n - 2);
}

echo "=== Test: Recursive Function Calls ===\n";

$fact = factorial(5);
echo "factorial(5): " . $fact . "\n";

$fib = fibonacci(6);
echo "fibonacci(6): " . $fib . "\n";

?>
