<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Data;

use DateTimeImmutable;
use JardisSupport\Contract\Auth\TokenType;

final readonly class Token
{
    private function __construct(
        public string $value,
        public TokenType $type,
        public ?string $subject,
        /** @var array<string, mixed> */
        public array $claims,
        public ?DateTimeImmutable $expiresAt,
        public DateTimeImmutable $createdAt,
    ) {
    }

    /**
     * @param positive-int $length
     */
    public static function create(TokenType $type, int $length = 32): self
    {
        $value = bin2hex(random_bytes($length));

        return new self(
            value: $value,
            type: $type,
            subject: null,
            claims: [],
            expiresAt: null,
            createdAt: new DateTimeImmutable(),
        );
    }

    /**
     * @param positive-int $seconds
     */
    public function expiresIn(int $seconds): self
    {
        return new self(
            value: $this->value,
            type: $this->type,
            subject: $this->subject,
            claims: $this->claims,
            expiresAt: $this->createdAt->modify('+' . $seconds . ' seconds'),
            createdAt: $this->createdAt,
        );
    }

    public function forSubject(string $subject): self
    {
        return new self(
            value: $this->value,
            type: $this->type,
            subject: $subject,
            claims: $this->claims,
            expiresAt: $this->expiresAt,
            createdAt: $this->createdAt,
        );
    }

    /**
     * @param array<string, mixed> $claims
     */
    public function withClaims(array $claims): self
    {
        return new self(
            value: $this->value,
            type: $this->type,
            subject: $this->subject,
            claims: array_merge($this->claims, $claims),
            expiresAt: $this->expiresAt,
            createdAt: $this->createdAt,
        );
    }

    public function hash(): HashedToken
    {
        return HashedToken::fromToken($this);
    }

    public function isExpired(): bool
    {
        if ($this->expiresAt === null) {
            return false;
        }

        return $this->expiresAt < new DateTimeImmutable();
    }
}
