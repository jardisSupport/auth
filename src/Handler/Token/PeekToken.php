<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Handler\Token;

use JardisSupport\Auth\Data\HashedToken;
use JardisSupport\Auth\Exception\InvalidCredentialException;
use JardisSupport\Contract\Auth\HashedTokenInterface;
use JardisSupport\Contract\Auth\TokenStoreInterface;
use JardisSupport\Contract\Auth\TokenType;

/** Checks a one-time token like `RedeemToken` (find, type, expiry, revocation) but leaves it unconsumed. */
final class PeekToken
{
    public function __construct(
        private readonly TokenStoreInterface $tokenStore,
        private readonly VerifyToken $verifyToken,
    ) {
    }

    /**
     * @throws InvalidCredentialException unknown token or wrong type
     * @throws \JardisSupport\Auth\Exception\TokenExpiredException
     * @throws \JardisSupport\Auth\Exception\TokenRevokedException
     */
    public function __invoke(string $plainToken, TokenType $expectedType): HashedTokenInterface
    {
        $stored = $this->tokenStore->find(HashedToken::hashOf($plainToken));

        if ($stored === null) {
            throw new InvalidCredentialException('Invalid token');
        }

        if (!($this->verifyToken)($plainToken, $stored, $expectedType)) {
            throw new InvalidCredentialException('Invalid token');
        }

        return $stored;
    }
}
