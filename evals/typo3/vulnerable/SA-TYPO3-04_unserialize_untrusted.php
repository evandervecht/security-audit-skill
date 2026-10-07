<?php
declare(strict_types=1);

use TYPO3\CMS\Core\Utility\GeneralUtility;

final class FlexFormProcessor
{
    public function process(array $row): array
    {
        // VULNERABLE: unserialize of DB-stored data and request data
        $config = unserialize($row['pi_flexform']);
        $state = unserialize(GeneralUtility::_GP('state'));

        return [$config, $state];
    }
}
