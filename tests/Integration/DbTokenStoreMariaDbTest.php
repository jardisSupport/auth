<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Tests\Integration;

use JardisAdapter\DbConnection\Factory\ConnectionFactory;
use JardisSupport\Contract\DbConnection\DbConnectionInterface;

/** DbTokenStore against the real MariaDB service of support/docker-compose.yml. */
final class DbTokenStoreMariaDbTest extends DbTokenStoreTestCase
{
    protected function createConnection(): DbConnectionInterface
    {
        return (new ConnectionFactory())->mysql(
            host: (string) getenv('MARIADB_HOST'),
            user: (string) getenv('MARIADB_USER'),
            password: (string) getenv('MARIADB_PASSWORD'),
            database: (string) getenv('MARIADB_DATABASE'),
            port: (int) getenv('MARIADB_PORT'),
        );
    }
}
