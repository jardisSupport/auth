<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Data\Event;

use DateTimeImmutable;

/** Domain event emitted when a session is refreshed, recording the old and new token hashes. */
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
