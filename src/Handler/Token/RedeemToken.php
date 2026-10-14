<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Handler\Token;

use JardisSupport\Auth\Data\HashedToken;
use JardisSupport\Auth\Exception\InvalidCredentialException;
use JardisSupport\Contract\Auth\HashedTokenInterface;
use JardisSupport\Contract\Auth\TokenStoreInterface;
use JardisSupport\Contract\Auth\TokenType;

/** Redeems a one-time token: finds it, verifies type, expiry and revocation, then revokes it. */
final class RedeemToken
{
    public function __construct(
        private readonly TokenStoreInterface $tokenStore,
        private readonly VerifyToken $verifyToken,
    ) {
    }

    /**
     * @throws InvalidCredentialException unknown token or wrong type
     * @throws \JardisSupport\Auth\Exception\TokenExpiredException
     * @throws \JardisSupport\Auth\Exception\TokenRevokedException (also on a second redemption)
     */
    public function __invoke(string $plainToken, TokenType $expectedType): HashedTokenInterface
    {
        $hash = HashedToken::hashOf($plainToken);
        $stored = $this->tokenStore->find($hash);

        if ($stored === null) {
            throw new InvalidCredentialException('Invalid token');
        }

        if (!($this->verifyToken)($plainToken, $stored, $expectedType)) {
            throw new InvalidCredentialException('Invalid token');
        }

        $this->tokenStore->revoke($hash);

        return $stored;
    }
}
