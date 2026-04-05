<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Data\Event;

use DateTimeImmutable;

final readonly class AuthenticationSucceeded
{
    public function __construct(
        public string $subject,
        public DateTimeImmutable $timestamp,
    ) {
    }
}
