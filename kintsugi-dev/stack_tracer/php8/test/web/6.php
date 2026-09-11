<?php
function helper_function($value) {
    return $value * 2;
}

echo "=== Test: Anonymous Functions ===\n";

$simple_closure = function($x) {
    return $x + 10;
};

echo "Closure result: " . $simple_closure(5) . "\n";

$multiplier = 3;
$closure_with_use = function($x) use ($multiplier) {
    return helper_function($x) * $multiplier;
};

echo "Closure with use result: " . $closure_with_use(4) . "\n";

$nested_closure = function($x) {
    $inner = function($y) {
        return $y * $y;
    };
    return $inner($x) + 5;
};

echo "Nested closure result: " . $nested_closure(6) . "\n";

?>
