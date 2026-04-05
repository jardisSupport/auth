<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Data;

final class PolicyBuilder
{
    /** @var array<string, array{allow: list<Permission>, deny: list<Permission>, includes: list<string>}> */
    private array $roles = [];

    private ?string $currentRole = null;

    public function role(string $name): self
    {
        if (!isset($this->roles[$name])) {
            $this->roles[$name] = ['allow' => [], 'deny' => [], 'includes' => []];
        }

        $this->currentRole = $name;

        return $this;
    }

    public function allow(string ...$permissions): self
    {
        $this->ensureCurrentRole();

        foreach ($permissions as $permission) {
            $this->roles[$this->currentRole]['allow'][] = Permission::from($permission);
        }

        return $this;
    }

    public function deny(string ...$permissions): self
    {
        $this->ensureCurrentRole();

        foreach ($permissions as $permission) {
            $this->roles[$this->currentRole]['deny'][] = Permission::from($permission);
        }

        return $this;
    }

    public function includes(string ...$roles): self
    {
        $this->ensureCurrentRole();

        foreach ($roles as $role) {
            $this->roles[$this->currentRole]['includes'][] = $role;
        }

        return $this;
    }

    public function build(): Policy
    {
        return Policy::fromArray($this->roles);
    }

    private function ensureCurrentRole(): void
    {
        if ($this->currentRole === null) {
            throw new \LogicException('Call role() before allow(), deny(), or includes()');
        }
    }
}
