<?php
declare(strict_types=1);

use TYPO3\CMS\Core\Utility\GeneralUtility;

final class SearchController
{
    public function searchAction(): void
    {
        $search = htmlspecialchars((string)GeneralUtility::_GP('q'));
        $page = (int)GeneralUtility::_GET('page');

        $this->queryBuilder->where(
            $this->queryBuilder->expr()->like(
                'title',
                $this->queryBuilder->createNamedParameter('%' . $search . '%')
            )
        );
        echo '<h1>Results</h1>';
    }
}
