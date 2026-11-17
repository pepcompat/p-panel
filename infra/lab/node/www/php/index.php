<?php
// Legacy PHP fixture (node-a, 02-php-legacy). Prints only non-sensitive facts.
header('Content-Type: text/plain');
echo "php-legacy ok host=" . htmlspecialchars($_SERVER['HTTP_HOST'] ?? '') . " php=" . PHP_VERSION . "\n";
