<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Handler\Authentication;

use JardisSupport\Auth\Data\AuthenticationResult;
use JardisSupport\Auth\Data\AuthResult;
use JardisSupport\Auth\Data\Session;
use JardisSupport\Auth\Data\SessionResult;

final class BuildAuthResult
{
    /**
     * @param list<object> $events
     */
    public function __invoke(
        AuthResult $authResult,
        ?SessionResult $sessionResult,
        array $events,
    ): AuthenticationResult {
        return new AuthenticationResult(
            authResult: $authResult,
            session: $sessionResult?->session,
            accessToken: $sessionResult?->accessToken,
            refreshToken: $sessionResult?->refreshToken,
            events: array_merge($sessionResult !== null ? $sessionResult->events : [], $events),
        );
    }
}
