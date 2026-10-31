<?php
// TEST DATA FIXTURE - VULNERABLE PHP PATTERNS

function handleRequest($conn, $userId) {
    // SQL Injection via concatenation (ENT-PHP-001)
    $sql = "SELECT * FROM users WHERE id = '" . $userId . "'";
    mysqli_query($conn, $sql);

    // Arbitrary command execution (ENT-PHP-002)
    $cmd = "ping " . $userId;
    system($cmd);
    eval('$res = ' . $userId . ';');

    // Unsafe dynamic file inclusion (ENT-PHP-003)
    $page = $_GET['page'];
    include $page;
}
?>
