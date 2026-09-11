<?php
class TestClass {
    private $name;

    public function __construct($name) {
        $this->name = $name;
    }

    public function sayHello() {
        return "Hello from " . $this->name;
    }

    public function calculate($a, $b) {
        return $this->multiply($a, $b);
    }

    private function multiply($x, $y) {
        return $x * $y;
    }
}

echo "=== Test: Instance Method Calls ===\n";

$obj = new TestClass("TestObj");
echo $obj->sayHello() . "\n";

$result = $obj->calculate(6, 7);
echo "Result: " . $result . "\n";

?>
