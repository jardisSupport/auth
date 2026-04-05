<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Handler\Authorization;

use JardisSupport\Auth\Data\Policy;
use JardisSupport\Contract\Auth\SessionInterface;

final class CheckPermission
{
    public function __construct(
        private readonly Policy $policy,
    ) {
    }

    public function __invoke(SessionInterface $session, string $permission): bool
    {
        $role = $session->getMetadata()['role'] ?? null;

        if (is_string($role)) {
            return $this->policy->isAllowed($role, $permission);
        }

        if (is_array($role)) {
            foreach ($role as $singleRole) {
                if (is_string($singleRole) && $this->policy->isAllowed($singleRole, $permission)) {
                    return true;
                }
            }
        }

        return false;
    }
}
