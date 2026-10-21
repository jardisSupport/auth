<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Handler\Authorization;

use JardisSupport\Auth\Data\Permission;

/**
 * Checks whether a right is contained in a list of granted rights (`resource:action`, `resource:*`, `*`).
 * A right that cannot be parsed throws `InvalidArgumentException` from `Permission::from()`.
 */
final class HasRight
{
    /** @param list<string> $rights */
    public function __invoke(array $rights, string $right): bool
    {
        $required = Permission::from($right);

        foreach ($rights as $granted) {
            if (Permission::from($granted)->matches($required)) {
                return true;
            }
        }

        return false;
    }
}
