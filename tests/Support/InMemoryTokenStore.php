<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Tests\Support;

use JardisSupport\Auth\Data\HashedToken;
use JardisSupport\Contract\Auth\HashedTokenInterface;
use JardisSupport\Contract\Auth\TokenStoreInterface;

final class InMemoryTokenStore implements TokenStoreInterface
{
    /** @var array<string, HashedToken> */
    private array $tokens = [];

    public function store(HashedTokenInterface $token): void
    {
        assert($token instanceof HashedToken);
        $this->tokens[$token->hash] = $token;
    }

    public function find(string $hash): ?HashedTokenInterface
    {
        return $this->tokens[$hash] ?? null;
    }

    public function revoke(string $hash): void
    {
        if (isset($this->tokens[$hash])) {
            $this->tokens[$hash] = $this->tokens[$hash]->withRevoked();
        }
    }

    public function revokeAllForSubject(string $subject): void
    {
        foreach ($this->tokens as $hash => $token) {
            if ($token->subject === $subject) {
                $this->tokens[$hash] = $token->withRevoked();
            }
        }
    }

    public function deleteExpired(): int
    {
        $count = 0;

        foreach ($this->tokens as $hash => $token) {
            if ($token->isExpired()) {
                unset($this->tokens[$hash]);
                $count++;
            }
        }

        return $count;
    }
}
