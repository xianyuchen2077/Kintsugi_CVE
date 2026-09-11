<?php
function outer_function($x) {
    echo "Entering outer_function, arg: " . $x . "\n";
    return middle_function($x * 2);
}

function middle_function($y) {
    echo "Entering middle_function, arg: " . $y . "\n";
    return inner_function($y + 10);
}

function inner_function($z) {
    echo "Entering inner_function, arg: " . $z . "\n";
    return $z * 3;
}

echo "=== Test: Nested Function Calls ===\n";

$result = outer_function(5);
echo "Final result: " . $result . "\n";

?>
