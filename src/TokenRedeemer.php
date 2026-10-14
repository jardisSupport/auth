<?php

declare(strict_types=1);

namespace JardisSupport\Auth;

use Closure;
use JardisSupport\Auth\Handler\Token\RedeemToken;
use JardisSupport\Auth\Handler\Token\VerifyToken;
use JardisSupport\Contract\Auth\HashedTokenInterface;
use JardisSupport\Contract\Auth\TokenStoreInterface;
use JardisSupport\Contract\Auth\TokenType;

/**
 * Orchestrates one-time redemption of a token: unknown, wrong type, expired or already redeemed tokens
 * throw; a valid token is revoked and returned with its subject and claims.
 */
final class TokenRedeemer
{
    private readonly Closure $redeemToken;

    public function __construct(
        TokenStoreInterface $tokenStore,
        VerifyToken $verifyToken = new VerifyToken(),
    ) {
        $this->redeemToken = (new RedeemToken($tokenStore, $verifyToken))->__invoke(...);
    }

    /**
     * @throws \JardisSupport\Auth\Exception\InvalidCredentialException unknown token or wrong type
     * @throws \JardisSupport\Auth\Exception\TokenExpiredException
     * @throws \JardisSupport\Auth\Exception\TokenRevokedException
     */
    public function redeem(string $plainToken, TokenType $expectedType): HashedTokenInterface
    {
        return ($this->redeemToken)($plainToken, $expectedType);
    }
}
