<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Handler\Authentication;

use DateTimeImmutable;
use JardisSupport\Auth\Data\AuthenticationResult;
use JardisSupport\Auth\Data\AuthResult;
use JardisSupport\Auth\Data\Session;
use JardisSupport\Auth\Data\SessionResult;
use JardisSupport\Contract\Auth\SessionInterface;
use JardisSupport\Contract\Auth\SessionResultInterface;

/** Assembles an AuthenticationResult from an auth outcome, optional session data, and collected events. */
final class BuildAuthResult
{
    /**
     * @param list<object> $events
     */
    public function __invoke(
        AuthResult $authResult,
        ?SessionResultInterface $sessionResult,
        array $events,
    ): AuthenticationResult {
        return new AuthenticationResult(
            authResult: $authResult,
            session: $sessionResult !== null ? $this->toSession($sessionResult->getSession()) : null,
            accessToken: $sessionResult?->getAccessToken(),
            refreshToken: $sessionResult?->getRefreshToken(),
            events: array_merge($sessionResult instanceof SessionResult ? $sessionResult->events : [], $events),
        );
    }

    /** A foreign `SessionInterface` is copied into the package's `Session`; the package's own is passed through. */
    private function toSession(SessionInterface $session): Session
    {
        return $session instanceof Session ? $session : new Session(
            subject: $session->getSubject(),
            tokenHash: $session->getTokenHash(),
            createdAt: new DateTimeImmutable(),
            expiresAt: null,
            metadata: $session->getMetadata(),
        );
    }
}
