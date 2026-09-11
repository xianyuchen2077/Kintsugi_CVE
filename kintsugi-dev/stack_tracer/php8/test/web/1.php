<?php
function simple_function() {
    return "Hello World";
}

function add_numbers($a, $b) {
    return $a + $b;
}

echo "=== Test: Simple Function Calls ===\n";

$result1 = simple_function();
echo "Result 1: " . $result1 . "\n";

$result2 = add_numbers(10, 20);
echo "Result 2: " . $result2 . "\n";

?>
