<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Data;

use JardisSupport\Contract\Auth\AuthResultInterface;

/** Immutable result of an authentication attempt, combining auth outcome, session data, tokens, and events. */
final readonly class AuthenticationResult implements AuthResultInterface
{
    /**
     * @param list<object> $events
     */
    public function __construct(
        public AuthResult $authResult,
        public ?Session $session,
        public ?string $accessToken,
        public ?string $refreshToken,
        public array $events = [],
    ) {
    }

    public function isSuccess(): bool
    {
        return $this->authResult->isSuccess();
    }

    public function getSubject(): ?string
    {
        return $this->authResult->getSubject();
    }

    public function getReason(): ?string
    {
        return $this->authResult->getReason();
    }
}
