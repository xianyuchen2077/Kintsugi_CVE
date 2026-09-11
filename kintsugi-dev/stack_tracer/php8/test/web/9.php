<?php
function risky_function($value) {
    if ($value < 0) {
        throw new Exception("Negative values not allowed");
    }
    return process_value($value);
}

function process_value($val) {
    return $val * 2 + 10;
}

function cleanup_function() {
    return "Cleanup done";
}

function safe_wrapper($input) {
    try {
        $result = risky_function($input);
        return "Success: " . $result;
    } catch (Exception $e) {
        error_handler($e);
        return "Failed: " . $e->getMessage();
    } finally {
        cleanup_function();
    }
}

function error_handler($exception) {
    return "Error handled: " . $exception->getMessage();
}

echo "=== Test: Exception Handling ===\n";

echo safe_wrapper(5) . "\n";

echo safe_wrapper(-3) . "\n";
?>
