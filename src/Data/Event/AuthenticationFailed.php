<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Data\Event;

use DateTimeImmutable;
use JardisSupport\Contract\Auth\CredentialType;

final readonly class AuthenticationFailed
{
    public function __construct(
        public CredentialType $credentialType,
        public string $reason,
        public DateTimeImmutable $timestamp,
    ) {
    }
}
