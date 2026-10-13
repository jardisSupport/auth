<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Handler\TokenStore;

use Closure;
use JardisSupport\Contract\Auth\HashedTokenInterface;
use JardisSupport\DbQuery\DbInsert;

/** Inserts a hashed token (hash only, never the plain value). */
final class StoreToken
{
    public function __construct(
        private readonly Closure $executeQuery,
        private readonly Closure $formatTimestamp,
        private readonly string $table,
    ) {
    }

    public function __invoke(HashedTokenInterface $token): void
    {
        $expiresAt = $token->getExpiresAt();

        ($this->executeQuery)(
            (new DbInsert())->into($this->table)->set([
                'token_hash' => $token->getHash(),
                'token_type' => $token->getType()->value,
                'subject' => $token->getSubject(),
                'claims' => json_encode($token->getClaims(), JSON_THROW_ON_ERROR),
                'expires_at' => $expiresAt === null ? null : ($this->formatTimestamp)($expiresAt),
                'created_at' => ($this->formatTimestamp)($token->getCreatedAt()),
                'revoked' => $token->isRevoked() ? 1 : 0,
            ])
        );
    }
}
