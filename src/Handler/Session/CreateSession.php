<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Handler\Session;

use JardisSupport\Auth\Data\Event\SessionCreated;
use JardisSupport\Auth\Data\Subject;
use JardisSupport\Auth\Data\Session;
use JardisSupport\Auth\Data\HashedToken;
use JardisSupport\Auth\Data\Token;
use JardisSupport\Contract\Auth\TokenType;
use JardisSupport\Contract\Auth\TokenStoreInterface;

/** Creates a new session by generating and storing hashed access and refresh tokens for a subject. */
final class CreateSession
{
    /** Internal claim on the access token: hash of the paired refresh token. */
    public const REFRESH_CLAIM = '_refresh';

    /** Internal claim on the refresh token: hash of the paired access token. */
    public const ACCESS_CLAIM = '_access';

    /** Prefix of package-internal claims; they never reach `Session::metadata`. */
    public const INTERNAL_PREFIX = '_';

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
        $claims = self::withoutInternal($claims);

        $accessToken = Token::create(TokenType::Access, $this->tokenLength);
        $refreshToken = Token::create(TokenType::Refresh, $this->tokenLength);

        // The pair link: each token carries the hash of its partner, so one can revoke the other.
        $accessToken = $accessToken
            ->forSubject($subject->toString())
            ->expiresIn($this->accessTokenTtl)
            ->withClaims($claims)
            ->withClaims([self::REFRESH_CLAIM => HashedToken::hashOf($refreshToken->value)]);

        $refreshToken = $refreshToken
            ->forSubject($subject->toString())
            ->expiresIn($this->refreshTokenTtl)
            ->withClaims($claims)
            ->withClaims([self::ACCESS_CLAIM => HashedToken::hashOf($accessToken->value)]);

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

    /**
     * Drops the package-internal claims (`_` prefix) so they are neither copied nor delivered.
     *
     * @param array<string, mixed> $claims
     * @return array<string, mixed>
     */
    public static function withoutInternal(array $claims): array
    {
        return array_filter(
            $claims,
            static fn (string|int $key): bool => !str_starts_with((string) $key, self::INTERNAL_PREFIX),
            ARRAY_FILTER_USE_KEY,
        );
    }
}
