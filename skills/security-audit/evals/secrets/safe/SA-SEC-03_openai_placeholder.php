<?php
// Placeholder / sample values only — pulled from env at runtime.
$openai = getenv("OPENAI_API_KEY") ?: "sk-proj-YOUR_KEY_HERE";
$sample = "sk-proj-EXAMPLE1234";
$tpl    = "sk-proj-xxxxxxxxxxxx";
$client = OpenAI::client($openai);
