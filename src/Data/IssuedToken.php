<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Data;

use JardisSupport\Contract\Auth\IssuedTokenInterface;

/** Result of issuing a one-time token: the plain value (hand it out once) and its hashed form as stored. */
final readonly class IssuedToken implements IssuedTokenInterface
{
    public function __construct(
        public string $plain,
        public HashedToken $hashed,
    ) {
    }

    public function getPlain(): string
    {
        return $this->plain;
    }

    public function getHashed(): HashedToken
    {
        return $this->hashed;
    }
}
