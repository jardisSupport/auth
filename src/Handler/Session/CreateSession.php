<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Handler\Session;

use JardisSupport\Auth\Data\Event\SessionCreated;
use JardisSupport\Auth\Data\Subject;
use JardisSupport\Auth\Data\Session;
use JardisSupport\Auth\Data\Token;
use JardisSupport\Contract\Auth\TokenType;
use JardisSupport\Contract\Auth\TokenStoreInterface;

final class CreateSession
{
    /**
     * @param positive-int $accessTokenTtl
     * @param positive-int $refreshTokenTtl
     * @param positive-int $tokenLength
     */
    public function __construct(
        private readonly TokenStoreInterface $tokenStore,
        private readonly int $accessTokenTtl,
        private readonly int $refreshTokenTtl,
        private readonly int $tokenLength,
    ) {
    }

    /**
     * @param array<string, mixed> $claims
     * @return array{session: Session, accessToken: string, refreshToken: string, events: list<SessionCreated>}
     */
    public function __invoke(Subject $subject, array $claims = []): array
    {
        $accessToken = Token::create(TokenType::Access, $this->tokenLength)
            ->forSubject($subject->toString())
            ->expiresIn($this->accessTokenTtl)
            ->withClaims($claims);

        $refreshToken = Token::create(TokenType::Refresh, $this->tokenLength)
            ->forSubject($subject->toString())
            ->expiresIn($this->refreshTokenTtl);

        $hashedAccess = $accessToken->hash();
        $hashedRefresh = $refreshToken->hash();

        $this->tokenStore->store($hashedAccess);
        $this->tokenStore->store($hashedRefresh);

        $session = new Session(
            subject: $subject->toString(),
            tokenHash: $hashedAccess->hash,
            createdAt: $accessToken->createdAt,
            expiresAt: $accessToken->expiresAt,
            metadata: $claims,
        );

        $event = new SessionCreated(
            subject: $subject->toString(),
            tokenHash: $hashedAccess->hash,
            timestamp: $accessToken->createdAt,
        );

        return [
            'session' => $session,
            'accessToken' => $accessToken->value,
            'refreshToken' => $refreshToken->value,
            'events' => [$event],
        ];
    }
}
