<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Data;

/** Result of issuing a one-time token: the plain value (hand it out once) and its hashed form as stored. */
final readonly class IssuedToken
{
    public function __construct(
        public string $plain,
        public HashedToken $hashed,
    ) {
    }
}
