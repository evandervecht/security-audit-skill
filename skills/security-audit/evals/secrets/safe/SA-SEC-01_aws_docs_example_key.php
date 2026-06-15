<?php
// Documentation placeholder — the official AWS docs example key, not a real credential.
// See https://docs.aws.amazon.com/IAM/latest/UserGuide/security-creds.html
$awsKeyExample = "AKIAIOSFODNN7EXAMPLE";
// Build the env var name from a prefix at runtime (no real key in source)
$placeholder = "AKIA" . "_PLACEHOLDER";
$client = new S3Client(['region' => 'eu-west-1']);
