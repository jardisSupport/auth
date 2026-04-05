<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Data\Event;

use DateTimeImmutable;

final readonly class SessionInvalidated
{
    public function __construct(
        public string $subject,
        public string $tokenHash,
        public DateTimeImmutable $timestamp,
    ) {
    }
}
