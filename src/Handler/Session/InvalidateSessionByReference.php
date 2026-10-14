<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Handler\Session;

use DateTimeImmutable;
use JardisSupport\Auth\Data\Event\SessionInvalidated;
use JardisSupport\Contract\Auth\TokenStoreInterface;

/**
 * Revokes exactly the session behind a session reference (hash of its access token) together with its
 * paired refresh token, so the session cannot be renewed afterwards.
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

        $pairedRefresh = $stored?->getClaims()[CreateSession::REFRESH_CLAIM] ?? null;

        if (is_string($pairedRefresh) && $pairedRefresh !== '') {
            $this->tokenStore->revoke($pairedRefresh);
        }

        return new SessionInvalidated(
            subject: $stored?->getSubject() ?? '',
            tokenHash: $sessionReference,
            timestamp: new DateTimeImmutable(),
        );
    }
}
