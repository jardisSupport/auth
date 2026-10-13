<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Handler\TokenStore;

use Closure;
use JardisSupport\DbQuery\DbUpdate;

/** Marks a single token as revoked; unknown hashes are a no-op. */
final class RevokeToken
{
    public function __construct(
        private readonly Closure $executeQuery,
        private readonly string $table,
    ) {
    }

    public function __invoke(string $hash): void
    {
        ($this->executeQuery)(
            (new DbUpdate())->table($this->table)->set('revoked', 1)->where('token_hash')->equals($hash)
        );
    }
}
