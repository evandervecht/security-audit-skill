<?php
// typo3conf/system/additional.php
$GLOBALS['TYPO3_CONF_VARS']['FE']['loginSecurityLevel'] = 'normal';
$GLOBALS['TYPO3_CONF_VARS']['BE']['loginSecurityLevel'] = 'normal';
$GLOBALS['TYPO3_CONF_VARS']['BE']['passwordHashing']['className'] = \TYPO3\CMS\Core\Crypto\PasswordHashing\Pbkdf2PasswordHash::class;
