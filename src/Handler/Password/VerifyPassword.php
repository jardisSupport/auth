<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Handler\Password;

/** Verifies a plain-text password against a stored password hash. */
final class VerifyPassword
{
    public function __invoke(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }
}
