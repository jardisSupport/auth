<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Data\Event;

use DateTimeImmutable;

/** Domain event emitted when a new session is successfully created for a subject. */
final readonly class SessionCreated
{
    public function __construct(
        public string $subject,
        public string $tokenHash,
        public DateTimeImmutable $timestamp,
    ) {
    }
}
