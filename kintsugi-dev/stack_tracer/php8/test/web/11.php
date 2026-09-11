<?php
// Test: external call chain recording logic
// f1 (in target path) -> f2 (outside target) -> f3 (outside target)
// Expected: f2 is recorded (call site f1 is in target), f3 is NOT recorded

require_once '/tmp/external_funcs.php';

function f1() {
    echo "f1: Calling f2 (defined outside target path)\n";
    $result = f2();
    echo "f1: f2 returned: $result\n";
    return "f1_result";
}

echo "=== Test: External Call Chain ===\n";
echo "Target path: /var/www/html\n";
echo "f1 defined in: /var/www/html (inside target)\n";
echo "f2 defined in: /tmp (outside target)\n";
echo "f3 defined in: /tmp (outside target)\n\n";

echo "Expected behavior:\n";
echo "- f1 -> f2: should be recorded (call site in target)\n";
echo "- f2 -> f3: should NOT be recorded (call site and definition both outside target)\n\n";

tracer_enable();

$result = f1();
echo "\nFinal result: $result\n";

tracer_disable();

?>
