<?php
// SA-04: Credential from environment variable (safe)
$dbCredential = getenv('DB_PASSWORD');
$db->connect($user, $dbCredential);
