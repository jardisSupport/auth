<?php

declare(strict_types=1);

namespace JardisSupport\Auth;

use Closure;
use JardisSupport\Auth\Handler\Password\CheckRehash;
use JardisSupport\Auth\Handler\Password\HashPassword;
use JardisSupport\Auth\Handler\Password\VerifyPassword;
use JardisSupport\Contract\Auth\PasswordHasherInterface;

/** Orchestrates password hashing and verification using Argon2id or bcrypt. */
final class PasswordHasher implements PasswordHasherInterface
{
    private readonly Closure $hashPassword;
    private readonly Closure $verifyPassword;
    private readonly Closure $checkRehash;

    /**
     * @param array<string, int> $options
     */
    public function __construct(string $algorithm = PASSWORD_ARGON2ID, array $options = [])
    {
        $this->hashPassword = (new HashPassword($algorithm, $options))->__invoke(...);
        $this->verifyPassword = (new VerifyPassword())->__invoke(...);
        $this->checkRehash = (new CheckRehash($algorithm, $options))->__invoke(...);
    }

    public static function argon2id(
        int $memoryCost = 65536,
        int $timeCost = 4,
        int $threads = 1,
    ): self {
        return new self(PASSWORD_ARGON2ID, [
            'memory_cost' => $memoryCost,
            'time_cost' => $timeCost,
            'threads' => $threads,
        ]);
    }

    public static function bcrypt(int $cost = 12): self
    {
        return new self(PASSWORD_BCRYPT, [
            'cost' => $cost,
        ]);
    }

    public function hash(string $password): string
    {
        return ($this->hashPassword)($password);
    }

    public function verify(string $password, string $hash): bool
    {
        return ($this->verifyPassword)($password, $hash);
    }

    public function needsRehash(string $hash): bool
    {
        return ($this->checkRehash)($hash);
    }
}
