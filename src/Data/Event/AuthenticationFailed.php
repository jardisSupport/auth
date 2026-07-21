<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Data\Event;

use DateTimeImmutable;
use JardisSupport\Contract\Auth\CredentialType;

/** Domain event emitted when an authentication attempt fails, recording the credential type and reason. */
final readonly class AuthenticationFailed
{
    public function __construct(
        public CredentialType $credentialType,
        public string $reason,
        public DateTimeImmutable $timestamp,
    ) {
    }
}
