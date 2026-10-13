<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Tests\Integration;

use JardisAdapter\DbConnection\Factory\ConnectionFactory;
use JardisSupport\Contract\DbConnection\DbConnectionInterface;

/** DbTokenStore against in-memory SQLite (second dialect, no service needed). */
final class DbTokenStoreSqliteTest extends DbTokenStoreTestCase
{
    protected function createConnection(): DbConnectionInterface
    {
        return (new ConnectionFactory())->sqlite();
    }
}
