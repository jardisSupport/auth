<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Tests\Support;

use JardisSupport\Contract\Auth\HashedTokenInterface;
use JardisSupport\Contract\Auth\TokenStoreInterface;

/** InMemoryTokenStore that counts `find()` calls. */
final class CountingTokenStore implements TokenStoreInterface
{
    public int $finds = 0;
    private InMemoryTokenStore $inner;

    public function __construct()
    {
        $this->inner = new InMemoryTokenStore();
    }

    public function store(HashedTokenInterface $token): void
    {
        $this->inner->store($token);
    }

    public function find(string $hash): ?HashedTokenInterface
    {
        $this->finds++;

        return $this->inner->find($hash);
    }

    public function revoke(string $hash): void
    {
        $this->inner->revoke($hash);
    }

    public function revokeAllForSubject(string $subject): void
    {
        $this->inner->revokeAllForSubject($subject);
    }

    public function deleteExpired(): int
    {
        return $this->inner->deleteExpired();
    }
}
