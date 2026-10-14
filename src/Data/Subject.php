<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Data;

/** Value object identifying an authenticated subject by id and type (e.g. user, service). */
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

    /**
     * Parses a qualified subject string (`type:id`). A string without a colon is a bare id of type `user`;
     * only the first colon separates type from id, so ids may contain colons.
     */
    public static function parse(string $qualified): self
    {
        $parts = explode(':', $qualified, 2);

        if (count($parts) === 2) {
            return new self($parts[1], $parts[0]);
        }

        return new self($qualified, 'user');
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
