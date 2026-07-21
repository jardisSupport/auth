<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Handler\Session;

use DateTimeImmutable;
use JardisSupport\Auth\Data\Event\SessionInvalidated;
use JardisSupport\Contract\Auth\SessionInterface;
use JardisSupport\Contract\Auth\TokenStoreInterface;

/** Revokes the token of a single session, invalidating it in the token store. */
final class InvalidateSession
{
    public function __construct(
        private readonly TokenStoreInterface $tokenStore,
    ) {
    }

    public function __invoke(SessionInterface $session): SessionInvalidated
    {
        $this->tokenStore->revoke($session->getTokenHash());

        return new SessionInvalidated(
            subject: $session->getSubject(),
            tokenHash: $session->getTokenHash(),
            timestamp: new DateTimeImmutable(),
        );
    }
}
