<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Handler\TokenStore;

use Closure;
use DateTimeImmutable;
use DateTimeZone;
use JardisSupport\Auth\Data\HashedToken;
use JardisSupport\Contract\Auth\HashedTokenInterface;
use JardisSupport\Contract\Auth\TokenType;
use JardisSupport\DbQuery\DbQuery;
use PDO;

/** Loads a hashed token by its hash, or null if unknown. */
final class FindToken
{
    public function __construct(
        private readonly Closure $executeQuery,
        private readonly string $table,
    ) {
    }

    public function __invoke(string $hash): ?HashedTokenInterface
    {
        $row = ($this->executeQuery)(
            (new DbQuery())
                ->select('token_hash, token_type, subject, claims, expires_at, created_at, revoked')
                ->from($this->table)
                ->where('token_hash')->equals($hash)
                ->limit(1)
        )->fetch(PDO::FETCH_ASSOC);

        if ($row === false) {
            return null;
        }

        $utc = new DateTimeZone('UTC');
        /** @var array<string, mixed> $claims */
        $claims = json_decode((string) $row['claims'], true, 512, JSON_THROW_ON_ERROR);

        return new HashedToken(
            hash: (string) $row['token_hash'],
            type: TokenType::from((string) $row['token_type']),
            subject: $row['subject'] === null ? null : (string) $row['subject'],
            claims: $claims,
            expiresAt: $row['expires_at'] === null ? null : new DateTimeImmutable((string) $row['expires_at'], $utc),
            createdAt: new DateTimeImmutable((string) $row['created_at'], $utc),
            revoked: (int) $row['revoked'] === 1,
        );
    }
}
