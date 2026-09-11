<?php
class StaticTestClass {
    private static $counter = 0;

    public static function getCounter() {
        return self::$counter;
    }

    public static function incrementCounter() {
        self::$counter++;
        return self::processIncrement();
    }

    private static function processIncrement() {
        return "Counter incremented to: " . self::$counter;
    }

    public static function chainedCall($value) {
        return self::doubleValue(self::addTen($value));
    }

    private static function addTen($n) {
        return $n + 10;
    }

    private static function doubleValue($n) {
        return $n * 2;
    }
}

echo "=== Test: Static Method Calls ===\n";

echo "Initial counter: " . StaticTestClass::getCounter() . "\n";

echo StaticTestClass::incrementCounter() . "\n";

$result = StaticTestClass::chainedCall(5);
echo "Chained call result: " . $result . "\n";

?>
