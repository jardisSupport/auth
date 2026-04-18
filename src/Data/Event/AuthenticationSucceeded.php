<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Data\Event;

use DateTimeImmutable;

/** Domain event emitted when a subject successfully authenticates. */
final readonly class AuthenticationSucceeded
{
    public function __construct(
        public string $subject,
        public DateTimeImmutable $timestamp,
    ) {
    }
}
