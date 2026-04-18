<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Data;

/** Immutable RBAC policy defining per-role allow, deny, and inheritance rules. */
final readonly class Policy
{
    /**
     * @param array<string, array{allow: list<Permission>, deny: list<Permission>, includes: list<string>}> $roles
     */
    private function __construct(
        private array $roles,
    ) {
    }

    public static function create(): PolicyBuilder
    {
        return new PolicyBuilder();
    }

    /**
     * @param array<string, array{allow: list<Permission>, deny: list<Permission>, includes: list<string>}> $roles
     */
    public static function fromArray(array $roles): self
    {
        return new self($roles);
    }

    public function isAllowed(string $role, string $permission): bool
    {
        return $this->checkPermission($role, Permission::from($permission), []);
    }

    /**
     * @param list<string> $visited
     */
    private function checkPermission(string $role, Permission $permission, array $visited): bool
    {
        if (!isset($this->roles[$role])) {
            return false;
        }

        if (in_array($role, $visited, true)) {
            return false;
        }

        $visited[] = $role;
        $roleConfig = $this->roles[$role];

        foreach ($roleConfig['deny'] as $denied) {
            if ($denied->matches($permission)) {
                return false;
            }
        }

        foreach ($roleConfig['allow'] as $allowed) {
            if ($allowed->matches($permission)) {
                return true;
            }
        }

        foreach ($roleConfig['includes'] as $includedRole) {
            if ($this->checkPermission($includedRole, $permission, $visited)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return list<string>
     */
    public function getRoles(): array
    {
        return array_keys($this->roles);
    }
}
