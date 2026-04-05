<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Handler\Session;

use DateTimeImmutable;
use JardisSupport\Auth\Data\Event\AllSessionsInvalidated;
use JardisSupport\Contract\Auth\TokenStoreInterface;

/** Revokes all active tokens for a subject, effectively invalidating all their sessions. */
final class InvalidateAllSessions
{
    public function __construct(
        private readonly TokenStoreInterface $tokenStore,
    ) {
    }

    public function __invoke(string $subject): AllSessionsInvalidated
    {
        $this->tokenStore->revokeAllForSubject($subject);

        return new AllSessionsInvalidated(
            subject: $subject,
            timestamp: new DateTimeImmutable(),
        );
    }
}
