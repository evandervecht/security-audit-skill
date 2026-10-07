<?php
declare(strict_types=1);

use TYPO3\CMS\Core\Utility\GeneralUtility;

final class SearchController
{
    public function searchAction(): void
    {
        $search = GeneralUtility::_GP('q');

        // VULNERABLE: user input concatenated into WHERE clause and echoed
        $this->queryBuilder->where('title LIKE \'%' . GeneralUtility::_GP('q') . '%\'');
        echo '<h1>Results for ' . GeneralUtility::_GP('q') . '</h1>';
    }
}
