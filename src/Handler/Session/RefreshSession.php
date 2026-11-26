<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Handler\Session;

use Closure;
use JardisSupport\Auth\Data\Event\SessionRefreshed;
use JardisSupport\Auth\Data\HashedToken;
use JardisSupport\Auth\Exception\AuthenticationException;
use JardisSupport\Auth\Handler\Token\VerifyToken;
use JardisSupport\Auth\Data\Subject;
use JardisSupport\Contract\Auth\TokenType;
use JardisSupport\Contract\Auth\TokenStoreInterface;

/**
 * Validates a refresh token, revokes it, and issues a new session with fresh access and refresh tokens.
 *
 * Only a refresh token is accepted: an unknown token and a valid token of another kind are both rejected with
 * `AuthenticationException('Invalid refresh token')` before anything is revoked, so a rejected token stays valid.
 */
final class RefreshSession
{
    /**
     * @param Closure(Subject, array<string, mixed>): array{
     *     session: \JardisSupport\Auth\Data\Session,
     *     accessToken: string,
     *     refreshToken: string,
     *     events: list<object>
     * } $createSession
     */
    public function __construct(
        private readonly TokenStoreInterface $tokenStore,
        private readonly VerifyToken $verifyToken,
        private readonly Closure $createSession,
    ) {
    }

    /**
     * @return array{
     *     session: \JardisSupport\Auth\Data\Session,
     *     accessToken: string,
     *     refreshToken: string,
     *     events: list<object>
     * }
     * @throws AuthenticationException unknown token or a token that is not a refresh token
     * @throws \JardisSupport\Auth\Exception\TokenExpiredException
     * @throws \JardisSupport\Auth\Exception\TokenRevokedException
     */
    public function __invoke(string $refreshTokenValue): array
    {
        $hash = HashedToken::hashOf($refreshTokenValue);
        $storedToken = $this->tokenStore->find($hash);

        if ($storedToken === null) {
            throw new AuthenticationException('Invalid refresh token');
        }

        if (!($this->verifyToken)($refreshTokenValue, $storedToken, TokenType::Refresh)) {
            throw new AuthenticationException('Invalid refresh token');
        }

        $this->tokenStore->revoke($hash);

        $subject = Subject::parse($storedToken->getSubject() ?? '');

        $createResult = ($this->createSession)($subject, CreateSession::withoutInternal($storedToken->getClaims()));

        $refreshedEvent = new SessionRefreshed(
            subject: $subject->toString(),
            oldTokenHash: $hash,
            newTokenHash: $createResult['session']->tokenHash,
            timestamp: $createResult['session']->createdAt,
        );

        return [
            'session' => $createResult['session'],
            'accessToken' => $createResult['accessToken'],
            'refreshToken' => $createResult['refreshToken'],
            'events' => [...$createResult['events'], $refreshedEvent],
        ];
    }
}
