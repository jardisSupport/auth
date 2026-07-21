<?php

declare(strict_types=1);

namespace JardisSupport\Auth;

use Closure;
use JardisSupport\Auth\Data\Event\AllSessionsInvalidated;
use JardisSupport\Auth\Data\Event\SessionInvalidated;
use JardisSupport\Auth\Data\SessionResult;
use JardisSupport\Auth\Data\Subject;
use JardisSupport\Auth\Handler\Session\CreateSession;
use JardisSupport\Auth\Handler\Session\InvalidateAllSessions;
use JardisSupport\Auth\Handler\Session\InvalidateSession;
use JardisSupport\Auth\Handler\Session\RefreshSession;
use JardisSupport\Auth\Handler\Token\VerifyToken;
use JardisSupport\Contract\Auth\SessionInterface;
use JardisSupport\Contract\Auth\TokenStoreInterface;

/** Orchestrates session lifecycle: creation, token refresh, and invalidation with event emission. */
final class SessionManager
{
    private readonly Closure $createSession;
    private readonly Closure $refreshSession;
    private readonly Closure $invalidateSession;
    private readonly Closure $invalidateAllSessions;

    /**
     * @param positive-int $accessTokenTtl
     * @param positive-int $refreshTokenTtl
     * @param positive-int $tokenLength
     */
    public function __construct(
        TokenStoreInterface $tokenStore,
        VerifyToken $verifyToken = new VerifyToken(),
        int $accessTokenTtl = 3600,
        int $refreshTokenTtl = 604800,
        int $tokenLength = 32,
    ) {
        $this->createSession = (new CreateSession(
            $tokenStore,
            $accessTokenTtl,
            $refreshTokenTtl,
            $tokenLength,
        ))->__invoke(...);

        $this->refreshSession = (new RefreshSession(
            $tokenStore,
            $verifyToken,
            $this->createSession,
        ))->__invoke(...);

        $this->invalidateSession = (new InvalidateSession($tokenStore))->__invoke(...);
        $this->invalidateAllSessions = (new InvalidateAllSessions($tokenStore))->__invoke(...);
    }

    /**
     * @param array<string, mixed> $claims
     */
    public function create(Subject $subject, array $claims = []): SessionResult
    {
        $result = ($this->createSession)($subject, $claims);

        return new SessionResult(
            session: $result['session'],
            accessToken: $result['accessToken'],
            refreshToken: $result['refreshToken'],
            events: $result['events'],
        );
    }

    public function refresh(string $refreshTokenValue): SessionResult
    {
        $result = ($this->refreshSession)($refreshTokenValue);

        return new SessionResult(
            session: $result['session'],
            accessToken: $result['accessToken'],
            refreshToken: $result['refreshToken'],
            events: $result['events'],
        );
    }

    public function invalidate(SessionInterface $session): SessionInvalidated
    {
        return ($this->invalidateSession)($session);
    }

    public function invalidateAll(string $subject): AllSessionsInvalidated
    {
        return ($this->invalidateAllSessions)($subject);
    }
}
