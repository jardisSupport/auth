<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Data\Event;

use DateTimeImmutable;

/** Domain event emitted when all active sessions for a subject are revoked at once. */
final readonly class AllSessionsInvalidated
{
    public function __construct(
        public string $subject,
        public DateTimeImmutable $timestamp,
    ) {
    }
}
