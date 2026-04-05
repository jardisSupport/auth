<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Data;

/** Value object representing a resource:action permission pair with wildcard and equality matching. */
final readonly class Permission
{
    private function __construct(
        public string $resource,
        public string $action,
    ) {
    }

    public static function from(string $permission): self
    {
        if ($permission === '*') {
            return new self('*', '*');
        }

        $parts = explode(':', $permission, 2);

        if (count($parts) !== 2) {
            throw new \InvalidArgumentException(
                'Permission must be in format "resource:action" or "*", got: ' . $permission
            );
        }

        return new self($parts[0], $parts[1]);
    }

    public function matches(self $other): bool
    {
        if ($this->resource === '*' && $this->action === '*') {
            return true;
        }

        if ($this->resource !== $other->resource) {
            return false;
        }

        return $this->action === '*' || $this->action === $other->action;
    }

    public function toString(): string
    {
        if ($this->resource === '*' && $this->action === '*') {
            return '*';
        }

        return $this->resource . ':' . $this->action;
    }

    public function equals(self $other): bool
    {
        return $this->resource === $other->resource && $this->action === $other->action;
    }
}
