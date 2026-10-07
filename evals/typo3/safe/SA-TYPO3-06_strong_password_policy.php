<?php
// typo3conf/system/additional.php
$GLOBALS['TYPO3_CONF_VARS']['FE']['loginSecurityLevel'] = 'rsa';
$GLOBALS['TYPO3_CONF_VARS']['BE']['passwordHashing']['className'] = \TYPO3\CMS\Core\Crypto\PasswordHashing\Argon2idPasswordHash::class;
