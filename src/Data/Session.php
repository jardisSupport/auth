<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Data;

use DateTimeImmutable;
use JardisSupport\Contract\Auth\SessionInterface;

final readonly class Session implements SessionInterface
{
    /**
     * @param array<string, mixed> $metadata
     */
    public function __construct(
        public string $subject,
        public string $tokenHash,
        public DateTimeImmutable $createdAt,
        public ?DateTimeImmutable $expiresAt,
        public array $metadata = [],
    ) {
    }

    public function getSubject(): string
    {
        return $this->subject;
    }

    public function getTokenHash(): string
    {
        return $this->tokenHash;
    }

    public function isExpired(): bool
    {
        if ($this->expiresAt === null) {
            return false;
        }

        return $this->expiresAt < new DateTimeImmutable();
    }

    /**
     * @return array<string, mixed>
     */
    public function getMetadata(): array
    {
        return $this->metadata;
    }

    /**
     * @param array<string, mixed> $metadata
     */
    public function withMetadata(array $metadata): self
    {
        return new self(
            subject: $this->subject,
            tokenHash: $this->tokenHash,
            createdAt: $this->createdAt,
            expiresAt: $this->expiresAt,
            metadata: array_merge($this->metadata, $metadata),
        );
    }
}
