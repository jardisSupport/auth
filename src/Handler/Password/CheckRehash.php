<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Handler\Password;

/** Checks whether a password hash needs to be rehashed due to algorithm or option changes. */
final class CheckRehash
{
    /**
     * @param array<string, int> $options
     */
    public function __construct(
        private readonly string $algorithm,
        private readonly array $options,
    ) {
    }

    public function __invoke(string $hash): bool
    {
        return password_needs_rehash($hash, $this->algorithm, $this->options);
    }
}
