<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Data;

use JardisSupport\Contract\Auth\SessionResultInterface;

/** Immutable value object carrying a created session, its token strings, and associated events. */
final readonly class SessionResult implements SessionResultInterface
{
    /**
     * @param list<object> $events
     */
    public function __construct(
        public Session $session,
        public string $accessToken,
        public string $refreshToken,
        public array $events = [],
    ) {
    }

    public function getAccessToken(): string
    {
        return $this->accessToken;
    }

    public function getRefreshToken(): string
    {
        return $this->refreshToken;
    }

    public function getSession(): Session
    {
        return $this->session;
    }
}
