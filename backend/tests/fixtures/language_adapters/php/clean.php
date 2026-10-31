<?php
// TEST DATA FIXTURE - CLEAN PHP PATTERNS

function handleRequestSafe(PDO $pdo, string $userId) {
    // Safe parameterized query with PDO
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
    $stmt->execute(['id' => $userId]);
    $user = $stmt->fetch();

    // Static include with whitelist validation
    $allowed = ['home', 'dashboard', 'settings'];
    $page = in_array($userId, $allowed, true) ? $userId : 'home';
    require_once __DIR__ . '/views/' . $page . '.php';

    return $user;
}
?>
