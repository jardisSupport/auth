<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Handler\Authentication;

use Closure;
use JardisSupport\Auth\Data\Subject;

/** Looks up a user's credential hash, subject, and claims by identifier via an injected closure. */
final class LookupUser
{
    /**
     * @param Closure(string): ?array{hash: string, subject: Subject, claims?: array<string, mixed>} $userLookup
     */
    public function __construct(
        private readonly Closure $userLookup,
    ) {
    }

    /**
     * @return ?array{hash: string, subject: Subject, claims?: array<string, mixed>}
     */
    public function __invoke(string $identifier): ?array
    {
        return ($this->userLookup)($identifier);
    }
}
