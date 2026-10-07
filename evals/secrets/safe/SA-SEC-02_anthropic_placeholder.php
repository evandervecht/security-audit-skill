<?php
// Placeholders and docs examples only — no real credential present.
$apiKey      = getenv("ANTHROPIC_API_KEY") ?: "sk-ant-YOUR_KEY_HERE";
$docExample  = "sk-ant-EXAMPLE";
$templateVal = "sk-ant-xxxxxxxx";
$client = new Anthropic\Client($apiKey);
