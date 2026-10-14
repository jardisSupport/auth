<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Data;

use JardisSupport\Contract\Auth\SessionAwareAuthResultInterface;

/**
 * Immutable authentication outcome of a resolved token session: qualified subject (`type:id`),
 * bare subject id, tenant and the session reference (hash of the presented access token).
 */
final readonly class TenantAuthResult implements SessionAwareAuthResultInterface
{
    private function __construct(
        public bool $success,
        public ?string $subject,
        public ?string $subjectId,
        public ?string $tenant,
        public ?string $sessionReference,
        public ?string $reason,
    ) {
    }

    public static function success(string $subject, ?string $tenant, ?string $sessionReference = null): self
    {
        return new self(true, $subject, Subject::parse($subject)->id, $tenant, $sessionReference, null);
    }

    public static function failure(string $reason): self
    {
        return new self(false, null, null, null, null, $reason);
    }

    public function isSuccess(): bool
    {
        return $this->success;
    }

    public function getSubject(): ?string
    {
        return $this->subject;
    }

    public function getSubjectId(): ?string
    {
        return $this->subjectId;
    }

    public function getTenant(): ?string
    {
        return $this->tenant;
    }

    public function getSessionReference(): ?string
    {
        return $this->sessionReference;
    }

    public function getReason(): ?string
    {
        return $this->reason;
    }
}
