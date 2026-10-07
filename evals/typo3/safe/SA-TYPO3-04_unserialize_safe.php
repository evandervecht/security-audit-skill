<?php
declare(strict_types=1);

use TYPO3\CMS\Core\Utility\GeneralUtility;

final class FlexFormProcessor
{
    public function process(array $row): array
    {
        // SAFE: structured parsing / disabled object instantiation
        $config = GeneralUtility::xml2array($row['pi_flexform']);
        $state = unserialize($row['state'], ['allowed_classes' => false]);
        $meta = json_decode((string)GeneralUtility::_GP('meta'), true);

        return [$config, $state, $meta];
    }
}
