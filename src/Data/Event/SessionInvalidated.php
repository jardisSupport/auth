<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Data\Event;

use DateTimeImmutable;

/** Domain event emitted when a single session token is revoked and the session is ended. */
final readonly class SessionInvalidated
{
    public function __construct(
        public string $subject,
        public string $tokenHash,
        public DateTimeImmutable $timestamp,
    ) {
    }
}
