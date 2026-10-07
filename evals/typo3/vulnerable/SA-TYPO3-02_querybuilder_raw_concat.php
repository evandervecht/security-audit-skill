<?php
declare(strict_types=1);

use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Utility\GeneralUtility;

final class PageRepository
{
    public function findByUid(int $uid): array
    {
        $connection = GeneralUtility::makeInstance(ConnectionPool::class)
            ->getConnectionForTable('pages');

        // VULNERABLE: raw SQL string concatenation
        return $connection->getConnection()->query('SELECT * FROM pages WHERE uid = ' . $uid)
            ->fetchAllAssociative();
    }
}
