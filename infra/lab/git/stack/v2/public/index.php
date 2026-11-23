<?php
// app: GET /healthz (DB reachable) · GET / inserts a hit and returns row counts as JSON.
const APP_VERSION = 'v2';
require __DIR__ . '/../db.php';
header('Content-Type: application/json');
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
try {
    $pdo = ppanel_db();
    if ($path === '/healthz') {
        $pdo->query('SELECT 1');
        echo json_encode(['status' => 'ok', 'version' => APP_VERSION]), "\n";
        return;
    }
    $pdo->prepare('INSERT INTO hits (version) VALUES (?)')->execute([APP_VERSION]);
    $hits = (int) $pdo->query('SELECT count(*) FROM hits')->fetchColumn();
    $beats = (int) $pdo->query('SELECT count(*) FROM heartbeats')->fetchColumn();
    echo json_encode(['version' => APP_VERSION, 'hits' => $hits, 'heartbeats' => $beats]), "\n";
} catch (Throwable $e) {
    http_response_code(503);
    echo json_encode(['status' => 'db-unavailable', 'version' => APP_VERSION]), "\n";
}
