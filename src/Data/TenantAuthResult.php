<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Data;

use JardisSupport\Contract\Auth\RightsAwareAuthResultInterface;
use JardisSupport\Contract\Auth\RoleAwareAuthResultInterface;
use JardisSupport\Contract\Auth\SessionAwareAuthResultInterface;

/**
 * Immutable authentication outcome of a resolved token session: qualified subject (`type:id`),
 * bare subject id, tenant, the session reference (hash of the presented access token) and the optional
 * role (claim `SessionClaim::ROLE`; `null` when the token carries none) and the rights (claim
 * `SessionClaim::RIGHTS`; `[]` when the token carries none).
 */
final readonly class TenantAuthResult implements
    SessionAwareAuthResultInterface,
    RoleAwareAuthResultInterface,
    RightsAwareAuthResultInterface
{
    private function __construct(
        public bool $success,
        public ?string $subject,
        public ?string $subjectId,
        public ?string $tenant,
        public ?string $sessionReference,
        public ?string $reason,
        public ?string $role = null,
        /** @var list<string> */
        public array $rights = [],
    ) {
    }

    /** @param list<string> $rights */
    public static function success(
        string $subject,
        ?string $tenant,
        ?string $sessionReference = null,
        ?string $role = null,
        array $rights = [],
    ): self {
        return new self(
            true,
            $subject,
            Subject::parse($subject)->id,
            $tenant,
            $sessionReference,
            null,
            $role,
            $rights,
        );
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

    public function getRole(): ?string
    {
        return $this->role;
    }

    /** @return list<string> */
    public function getRights(): array
    {
        return $this->rights;
    }

    public function getReason(): ?string
    {
        return $this->reason;
    }
}
