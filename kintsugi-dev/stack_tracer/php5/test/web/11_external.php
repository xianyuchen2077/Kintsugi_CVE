<?php
function f2() {
    echo "  f2: Inside f2 (defined outside target path)\n";
    echo "  f2: Calling f3 (also defined outside target path)\n";

    $result = f3();

    echo "  f2: f3 returned: $result\n";
    return "f2_result";
}

function f3() {
    echo "    f3: Inside f3 (defined outside target path)\n";
    return "f3_result";
}

?>
