<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Data;

final readonly class SessionResult
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
}
