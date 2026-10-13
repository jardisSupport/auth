<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Handler\TokenStore;

use InvalidArgumentException;
use JardisSupport\Contract\DbConnection\DbConnectionInterface;
use JardisSupport\Contract\DbQuery\DbPreparedQueryInterface;
use JardisSupport\Contract\DbQuery\DbSqlGeneratorInterface;
use PDOStatement;

/** Renders a dbquery builder for the connection's dialect and executes it as a prepared statement. */
final class ExecuteQuery
{
    public function __construct(private readonly DbConnectionInterface $connection)
    {
    }

    public function __invoke(DbSqlGeneratorInterface $builder): PDOStatement
    {
        $prepared = $builder->sql($this->dialect(), prepared: true);

        if (!$prepared instanceof DbPreparedQueryInterface) {
            throw new InvalidArgumentException('Token store queries must be rendered as prepared statements');
        }

        $statement = $this->connection->pdo()->prepare($prepared->sql());
        $statement->execute($prepared->bindings());

        return $statement;
    }

    private function dialect(): string
    {
        return match ($this->connection->getDriverName()) {
            'pgsql' => 'postgres',
            default => $this->connection->getDriverName(),
        };
    }
}
