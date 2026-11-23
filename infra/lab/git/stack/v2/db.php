<?php
// Shared DB helper: connection from env (DB_HOST/DB_NAME/DB_USER, DB_PASSWORD is a pPanel secret).
function ppanel_db(): PDO {
    $dsn = sprintf('pgsql:host=%s;port=5432;dbname=%s', getenv('DB_HOST') ?: 'db', getenv('DB_NAME') ?: 'app');
    $pdo = new PDO($dsn, getenv('DB_USER') ?: 'app', getenv('DB_PASSWORD') ?: '', [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_TIMEOUT => 3,
    ]);
    $pdo->exec('CREATE TABLE IF NOT EXISTS hits (id BIGSERIAL PRIMARY KEY, version TEXT NOT NULL, at TIMESTAMPTZ NOT NULL DEFAULT now())');
    $pdo->exec('CREATE TABLE IF NOT EXISTS heartbeats (id BIGSERIAL PRIMARY KEY, at TIMESTAMPTZ NOT NULL DEFAULT now())');
    return $pdo;
}
