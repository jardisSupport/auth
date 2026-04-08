<?php

declare(strict_types=1);

namespace JardisSupport\Auth;

use Closure;
use JardisSupport\Auth\Handler\Authorization\AuthorizePermission;
use JardisSupport\Auth\Handler\Authorization\CheckPermission;
use JardisSupport\Auth\Data\Policy;
use JardisSupport\Contract\Auth\GuardInterface;
use JardisSupport\Contract\Auth\SessionInterface;

/** Orchestrates role-based access control by checking and enforcing permissions against a policy. */
final class Guard implements GuardInterface
{
    private readonly Closure $checkPermission;
    private readonly Closure $authorizePermission;

    public function __construct(Policy $policy)
    {
        $this->checkPermission = (new CheckPermission($policy))->__invoke(...);
        $this->authorizePermission = (new AuthorizePermission($this->checkPermission))->__invoke(...);
    }

    public function check(SessionInterface $session, string $permission): bool
    {
        return ($this->checkPermission)($session, $permission);
    }

    public function authorize(SessionInterface $session, string $permission): void
    {
        ($this->authorizePermission)($session, $permission);
    }
}
