<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Handler\Token;

use JardisSupport\Auth\Exception\TokenExpiredException;
use JardisSupport\Auth\Exception\TokenRevokedException;
use JardisSupport\Contract\Auth\HashedTokenInterface;
use JardisSupport\Contract\Auth\TokenType;

final class VerifyToken
{
    public function __invoke(string $plainToken, HashedTokenInterface $stored, ?TokenType $expectedType = null): bool
    {
        $hash = hash('sha256', $plainToken);

        if (!hash_equals($stored->getHash(), $hash)) {
            return false;
        }

        if ($stored->isRevoked()) {
            throw new TokenRevokedException('Token has been revoked');
        }

        if ($stored->isExpired()) {
            throw new TokenExpiredException('Token has expired');
        }

        if ($expectedType !== null && $stored->getType() !== $expectedType) {
            return false;
        }

        return true;
    }
}
