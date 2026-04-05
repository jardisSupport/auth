<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Handler\Password;

final class HashPassword
{
    /**
     * @param array<string, int> $options
     */
    public function __construct(
        private readonly string $algorithm,
        private readonly array $options,
    ) {
    }

    public function __invoke(string $password): string
    {
        return password_hash($password, $this->algorithm, $this->options);
    }
}
