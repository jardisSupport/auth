<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Data;

final readonly class Subject
{
    private function __construct(
        public string $id,
        public string $type,
    ) {
    }

    public static function from(string $id, string $type = 'user'): self
    {
        return new self($id, $type);
    }

    public function equals(self $other): bool
    {
        return $this->id === $other->id && $this->type === $other->type;
    }

    public function toString(): string
    {
        return $this->type . ':' . $this->id;
    }
}
