<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Tests\Support;

use JardisSupport\Contract\DbConnection\DbConnectionInterface;

/** Test helper: (re)creates the shipped auth_tokens table from resources/sql/<driver>.sql. */
final class TokenTable
{
    public static function recreate(DbConnectionInterface $connection): void
    {
        $file = dirname(__DIR__, 2) . '/resources/sql/' . $connection->getDriverName() . '.sql';
        $ddl = (string) file_get_contents($file);

        $connection->pdo()->exec('DROP TABLE IF EXISTS auth_tokens');
        $connection->pdo()->exec($ddl);
    }
}
