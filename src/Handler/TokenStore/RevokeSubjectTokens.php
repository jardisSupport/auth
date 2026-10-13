<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Handler\TokenStore;

use Closure;
use JardisSupport\DbQuery\DbUpdate;

/** Marks every token of a subject as revoked. */
final class RevokeSubjectTokens
{
    public function __construct(
        private readonly Closure $executeQuery,
        private readonly string $table,
    ) {
    }

    public function __invoke(string $subject): void
    {
        ($this->executeQuery)(
            (new DbUpdate())->table($this->table)->set('revoked', 1)->where('subject')->equals($subject)
        );
    }
}
