<?php
// Worker: inserts a heartbeat row every 2 s; reconnects on errors (db may restart).
require __DIR__ . '/db.php';
fwrite(STDOUT, "worker starting\n");
$pdo = null;
while (true) {
    try {
        if ($pdo === null) {
            $pdo = ppanel_db();
            fwrite(STDOUT, "worker connected\n");
        }
        $pdo->exec('INSERT INTO heartbeats DEFAULT VALUES');
    } catch (Throwable $e) {
        fwrite(STDERR, 'worker db error: ' . $e->getMessage() . "\n");
        $pdo = null;
    }
    sleep(2);
}
