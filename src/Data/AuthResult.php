<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Data;

use JardisSupport\Contract\Auth\AuthResultInterface;

/** Immutable value object representing the outcome of an authentication attempt. */
final readonly class AuthResult implements AuthResultInterface
{
    private function __construct(
        public bool $success,
        public ?Subject $subject,
        public ?string $reason,
    ) {
    }

    public static function success(Subject $subject): self
    {
        return new self(true, $subject, null);
    }

    public static function failure(string $reason): self
    {
        return new self(false, null, $reason);
    }

    public function isSuccess(): bool
    {
        return $this->success;
    }

    public function getSubject(): ?string
    {
        return $this->subject?->toString();
    }

    public function getReason(): ?string
    {
        return $this->reason;
    }
}
