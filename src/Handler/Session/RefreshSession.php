<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Handler\Session;

use Closure;
use JardisSupport\Auth\Data\Event\SessionRefreshed;
use JardisSupport\Auth\Exception\AuthenticationException;
use JardisSupport\Auth\Handler\Token\VerifyToken;
use JardisSupport\Auth\Data\Subject;
use JardisSupport\Contract\Auth\TokenType;
use JardisSupport\Contract\Auth\TokenStoreInterface;

/** Validates a refresh token, revokes it, and issues a new session with fresh access and refresh tokens. */
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
     */
    public function __invoke(string $refreshTokenValue): array
    {
        $hash = hash('sha256', $refreshTokenValue);
        $storedToken = $this->tokenStore->find($hash);

        if ($storedToken === null) {
            throw new AuthenticationException('Invalid refresh token');
        }

        ($this->verifyToken)($refreshTokenValue, $storedToken, TokenType::Refresh);

        $this->tokenStore->revoke($hash);

        $subject = $this->parseSubject($storedToken->getSubject() ?? '');

        $createResult = ($this->createSession)($subject, $storedToken->getClaims());

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

    private function parseSubject(string $subjectString): Subject
    {
        $parts = explode(':', $subjectString, 2);

        if (count($parts) === 2) {
            return Subject::from($parts[1], $parts[0]);
        }

        return Subject::from($subjectString);
    }
}
