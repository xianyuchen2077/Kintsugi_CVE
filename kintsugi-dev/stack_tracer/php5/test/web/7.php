<?php
function process_data($data, $callback) {
    return $callback($data);
}

function transform_callback($value) {
    return "Processed: " . ($value * 2);
}

function array_processor($arr, $processor) {
    $result = array();
    foreach ($arr as $item) {
        $result[] = $processor($item);
    }
    return $result;
}

function square_number($n) {
    return $n * $n;
}

echo "=== Test: Callback Functions ===\n";

$result1 = process_data(15, 'transform_callback');
echo $result1 . "\n";

$numbers = array(2, 3, 4, 5);
$squared = array_processor($numbers, 'square_number');
echo "Squared: " . implode(", ", $squared) . "\n";

$result2 = process_data(8, function($x) { return "Anonymous callback: " . ($x + 100); });
echo $result2 . "\n";

?>
