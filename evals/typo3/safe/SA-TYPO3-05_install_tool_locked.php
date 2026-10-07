<?php
// typo3conf/system/additional.php
$GLOBALS['TYPO3_CONF_VARS']['BE']['installToolPassword'] = '$argon2id$v=19$m=65536,t=16,p=1$c29tZXNhbHQ$hashvalue';
$GLOBALS['TYPO3_CONF_VARS']['BE']['lockSSL'] = true;
