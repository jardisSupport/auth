<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Data;

use JardisSupport\Contract\Auth\TenantAwareAuthResultInterface;

/** Immutable authentication outcome that carries subject and tenant of a resolved token session. */
final readonly class TenantAuthResult implements TenantAwareAuthResultInterface
{
    private function __construct(
        public bool $success,
        public ?string $subject,
        public ?string $tenant,
        public ?string $reason,
    ) {
    }

    public static function success(string $subject, ?string $tenant): self
    {
        return new self(true, $subject, $tenant, null);
    }

    public static function failure(string $reason): self
    {
        return new self(false, null, null, $reason);
    }

    public function isSuccess(): bool
    {
        return $this->success;
    }

    public function getSubject(): ?string
    {
        return $this->subject;
    }

    public function getTenant(): ?string
    {
        return $this->tenant;
    }

    public function getReason(): ?string
    {
        return $this->reason;
    }
}
