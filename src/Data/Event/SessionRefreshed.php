<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Data\Event;

use DateTimeImmutable;

final readonly class SessionRefreshed
{
    public function __construct(
        public string $subject,
        public string $oldTokenHash,
        public string $newTokenHash,
        public DateTimeImmutable $timestamp,
    ) {
    }
}
