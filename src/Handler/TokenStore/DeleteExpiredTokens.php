<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Handler\TokenStore;

use Closure;
use DateTimeImmutable;
use JardisSupport\DbQuery\DbDelete;

/** Deletes all tokens whose expiry lies in the past and returns how many were removed. */
final class DeleteExpiredTokens
{
    public function __construct(
        private readonly Closure $executeQuery,
        private readonly Closure $formatTimestamp,
        private readonly string $table,
    ) {
    }

    public function __invoke(): int
    {
        return ($this->executeQuery)(
            (new DbDelete())
                ->from($this->table)
                ->where('expires_at')->isNotNull()
                ->and('expires_at')->lower(($this->formatTimestamp)(new DateTimeImmutable()))
        )->rowCount();
    }
}
