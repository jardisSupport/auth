<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Handler\Session;

use DateTimeImmutable;
use JardisSupport\Auth\Data\Event\SessionInvalidated;
use JardisSupport\Contract\Auth\TokenStoreInterface;

/**
 * Revokes exactly the session behind a session reference (`sid` = hash of its refresh token), so the
 * session cannot be renewed afterwards. An already issued access token stays valid until its `exp`.
 * Idempotent: an unknown reference revokes nothing and yields an event with an empty subject.
 */
final class InvalidateSessionByReference
{
    public function __construct(
        private readonly TokenStoreInterface $tokenStore,
    ) {
    }

    public function __invoke(string $sessionReference): SessionInvalidated
    {
        $stored = $this->tokenStore->find($sessionReference);
        $this->tokenStore->revoke($sessionReference);

        return new SessionInvalidated(
            subject: $stored?->getSubject() ?? '',
            tokenHash: $sessionReference,
            timestamp: new DateTimeImmutable(),
        );
    }
}
