<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Handler\Authentication;

use Closure;

/** Verifies a plain-text credential against a hash using an injected password-verification closure. */
final class VerifyCredential
{
    /**
     * @param Closure(string, string): bool $verifyPassword
     */
    public function __construct(
        private readonly Closure $verifyPassword,
    ) {
    }

    public function __invoke(string $password, string $hash): bool
    {
        return ($this->verifyPassword)($password, $hash);
    }
}
