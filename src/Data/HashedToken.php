<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Data;

use DateTimeImmutable;
use JardisSupport\Contract\Auth\HashedTokenInterface;
use JardisSupport\Contract\Auth\TokenType;

/** Immutable value object representing a SHA-256 hashed token with expiry and revocation state. */
final readonly class HashedToken implements HashedTokenInterface
{
    /**
     * @param array<string, mixed> $claims
     */
    public function __construct(
        public string $hash,
        public TokenType $type,
        public ?string $subject,
        public array $claims,
        public ?DateTimeImmutable $expiresAt,
        public DateTimeImmutable $createdAt,
        public bool $revoked = false,
    ) {
    }

    /** The one hash function for tokens: SHA-256 of the plain token value. Use it for every presented token. */
    public static function hashOf(string $plainToken): string
    {
        return hash('sha256', $plainToken);
    }

    public static function fromToken(Token $token): self
    {
        return new self(
            hash: self::hashOf($token->value),
            type: $token->type,
            subject: $token->subject,
            claims: $token->claims,
            expiresAt: $token->expiresAt,
            createdAt: $token->createdAt,
        );
    }

    public function getHash(): string
    {
        return $this->hash;
    }

    public function getType(): TokenType
    {
        return $this->type;
    }

    public function getSubject(): ?string
    {
        return $this->subject;
    }

    /**
     * @return array<string, mixed>
     */
    public function getClaims(): array
    {
        return $this->claims;
    }

    public function getExpiresAt(): ?DateTimeImmutable
    {
        return $this->expiresAt;
    }

    public function getCreatedAt(): DateTimeImmutable
    {
        return $this->createdAt;
    }

    public function isExpired(): bool
    {
        if ($this->expiresAt === null) {
            return false;
        }

        return $this->expiresAt < new DateTimeImmutable();
    }

    public function isRevoked(): bool
    {
        return $this->revoked;
    }

    public function withRevoked(): self
    {
        return new self(
            hash: $this->hash,
            type: $this->type,
            subject: $this->subject,
            claims: $this->claims,
            expiresAt: $this->expiresAt,
            createdAt: $this->createdAt,
            revoked: true,
        );
    }
}
