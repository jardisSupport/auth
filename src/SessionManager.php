<?php

declare(strict_types=1);

namespace JardisSupport\Auth;

use Closure;
use JardisSupport\Auth\Data\Event\SessionInvalidated;
use JardisSupport\Auth\Data\SessionResult;
use JardisSupport\Auth\Data\Subject;
use JardisSupport\Auth\Handler\Session\CreateSession;
use JardisSupport\Auth\Handler\Session\InvalidateAllSessions;
use JardisSupport\Auth\Handler\Session\InvalidateSession;
use JardisSupport\Auth\Handler\Session\InvalidateSessionByReference;
use JardisSupport\Auth\Handler\Session\RefreshSession;
use JardisSupport\Auth\Handler\Token\SignAccessToken;
use JardisSupport\Auth\Handler\Token\VerifyToken;
use JardisSupport\Contract\Auth\SessionInterface;
use JardisSupport\Contract\Auth\SessionManagerInterface;
use JardisSupport\Contract\Auth\TokenStoreInterface;

/**
 * Orchestrates session lifecycle: creation, token refresh, and invalidation with event emission.
 *
 * Access tokens are signed (verified without a store, see `SignedTokenAuthenticator`); refresh tokens are
 * opaque and live in the `TokenStoreInterface`. Revocation takes effect at the next refresh — an issued
 * access token stays valid until its expiry.
 *
 * The contract methods (`create`, `refresh`, `invalidateByReference`, `invalidateAll`) follow
 * `SessionManagerInterface`: subjects are qualified strings (`type:id`, a `Subject` is accepted too) and the
 * `invalidate*` calls return nothing. `invalidate(SessionInterface)` is not part of the contract and still
 * returns its event.
 */
final class SessionManager implements SessionManagerInterface
{
    private readonly Closure $createSession;
    private readonly Closure $refreshSession;
    private readonly Closure $invalidateSession;
    private readonly Closure $invalidateSessionByReference;
    private readonly Closure $invalidateAllSessions;

    /**
     * @param string $accessTokenKey raw 32-byte signing key (e.g. base64-decoded `AUTH_TOKEN_KEY`);
     *                               rotating it invalidates every issued access token
     * @param positive-int $accessTokenTtl
     * @param positive-int $refreshTokenTtl
     * @param positive-int $tokenLength
     */
    public function __construct(
        TokenStoreInterface $tokenStore,
        #[\SensitiveParameter] string $accessTokenKey,
        VerifyToken $verifyToken = new VerifyToken(),
        int $accessTokenTtl = 900,
        int $refreshTokenTtl = 604800,
        int $tokenLength = 32,
    ) {
        $this->createSession = (new CreateSession(
            $tokenStore,
            (new SignAccessToken($accessTokenKey))->__invoke(...),
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
        $this->invalidateSessionByReference = (new InvalidateSessionByReference($tokenStore))->__invoke(...);
        $this->invalidateAllSessions = (new InvalidateAllSessions($tokenStore))->__invoke(...);
    }

    /**
     * @param Subject|string $subject a `Subject` or its qualified string `type:id` (`Subject::parse`)
     * @param array<string, mixed> $claims
     */
    public function create(Subject|string $subject, array $claims = []): SessionResult
    {
        $subject = is_string($subject) ? Subject::parse($subject) : $subject;
        $result = ($this->createSession)($subject, $claims);

        return new SessionResult(
            session: $result['session'],
            accessToken: $result['accessToken'],
            refreshToken: $result['refreshToken'],
            events: $result['events'],
        );
    }

    public function refresh(string $refreshToken): SessionResult
    {
        $result = ($this->refreshSession)($refreshToken);

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

    /**
     * Revokes exactly the session behind a session reference, e.g. `getSessionReference()` of the
     * authentication result. Other sessions of the same subject stay valid.
     */
    public function invalidateByReference(string $sessionReference): void
    {
        ($this->invalidateSessionByReference)($sessionReference);
    }

    public function invalidateAll(string $subject): void
    {
        ($this->invalidateAllSessions)($subject);
    }
}
