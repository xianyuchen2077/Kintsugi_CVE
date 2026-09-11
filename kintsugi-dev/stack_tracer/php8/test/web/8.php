<?php
function user_function_before_builtin($str) {
    return "Pre-processed: " . $str;
}

function user_function_after_builtin($result) {
    return "Post-processed: " . $result;
}

echo "=== Test: Built-in Function Calls ===\n";

$str = user_function_before_builtin("hello world");
$upper = strtoupper($str);
$result1 = user_function_after_builtin($upper);
echo $result1 . "\n";

$arr = array(3, 1, 4, 1, 5, 9, 2, 6);
sort($arr);
echo "Array sorted.\n";

$num = 16;
$sqrt_result = sqrt($num);
echo "sqrt(16): " . $sqrt_result . "\n";

$timestamp = time();
$date_str = date('Y-m-d H:i:s', $timestamp);
echo "Current time: " . $date_str . "\n";

?>
