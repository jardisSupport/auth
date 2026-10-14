<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Handler\Session;

use Closure;
use DateTimeImmutable;
use JardisSupport\Auth\Data\Event\SessionCreated;
use JardisSupport\Auth\Data\Subject;
use JardisSupport\Auth\Data\Session;
use JardisSupport\Auth\Data\Token;
use JardisSupport\Contract\Auth\TokenType;
use JardisSupport\Contract\Auth\TokenStoreInterface;

/**
 * Creates a new session: an opaque refresh token (hashed in the store) and a signed access token that
 * carries the refresh token's hash as `sid`. The access token itself is never stored.
 */
final class CreateSession
{
    /** Prefix of package-internal claims; they never reach `Session::metadata`. */
    public const INTERNAL_PREFIX = '_';

    /**
     * @param Closure(array<string, mixed>): string $signAccessToken
     * @param positive-int $accessTokenTtl
     * @param positive-int $refreshTokenTtl
     * @param positive-int $tokenLength
     */
    public function __construct(
        private readonly TokenStoreInterface $tokenStore,
        private readonly Closure $signAccessToken,
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

        $refreshToken = Token::create(TokenType::Refresh, $this->tokenLength)
            ->forSubject($subject->toString())
            ->expiresIn($this->refreshTokenTtl)
            ->withClaims($claims);

        $hashedRefresh = $refreshToken->hash();
        $this->tokenStore->store($hashedRefresh);

        $issuedAt = $refreshToken->createdAt->getTimestamp();
        $expiresAt = $issuedAt + $this->accessTokenTtl;

        $accessToken = ($this->signAccessToken)([
            'typ' => 'access',
            'sub' => $subject->toString(),
            'sid' => $hashedRefresh->hash,
            'iat' => $issuedAt,
            'exp' => $expiresAt,
            'claims' => $claims,
        ]);

        $session = new Session(
            subject: $subject->toString(),
            tokenHash: $hashedRefresh->hash,
            createdAt: $refreshToken->createdAt,
            expiresAt: (new DateTimeImmutable())->setTimestamp($expiresAt),
            metadata: $claims,
        );

        $event = new SessionCreated(
            subject: $subject->toString(),
            tokenHash: $hashedRefresh->hash,
            timestamp: $refreshToken->createdAt,
        );

        return [
            'session' => $session,
            'accessToken' => $accessToken,
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
