<?php

declare(strict_types=1);

namespace JardisSupport\Auth;

use Closure;
use JardisSupport\Auth\Handler\Token\PeekToken;
use JardisSupport\Auth\Handler\Token\RedeemToken;
use JardisSupport\Auth\Handler\Token\VerifyToken;
use JardisSupport\Contract\Auth\HashedTokenInterface;
use JardisSupport\Contract\Auth\TokenRedeemerInterface;
use JardisSupport\Contract\Auth\TokenStoreInterface;
use JardisSupport\Contract\Auth\TokenType;

/**
 * Orchestrates checking and one-time redemption of a token: unknown, wrong type, expired or already redeemed
 * tokens throw. `peek` returns a valid token unconsumed; `redeem` revokes it and returns it with its subject
 * and claims.
 */
final class TokenRedeemer implements TokenRedeemerInterface
{
    private readonly Closure $peekToken;
    private readonly Closure $redeemToken;

    public function __construct(
        TokenStoreInterface $tokenStore,
        VerifyToken $verifyToken = new VerifyToken(),
    ) {
        $this->peekToken = (new PeekToken($tokenStore, $verifyToken))->__invoke(...);
        $this->redeemToken = (new RedeemToken($tokenStore, $verifyToken))->__invoke(...);
    }

    /**
     * Verifies the token exactly like `redeem` but does not revoke it — the token stays redeemable.
     *
     * @throws \JardisSupport\Auth\Exception\InvalidCredentialException unknown token or wrong type
     * @throws \JardisSupport\Auth\Exception\TokenExpiredException
     * @throws \JardisSupport\Auth\Exception\TokenRevokedException
     */
    public function peek(string $plain, TokenType $expected): HashedTokenInterface
    {
        return ($this->peekToken)($plain, $expected);
    }

    /**
     * @throws \JardisSupport\Auth\Exception\InvalidCredentialException unknown token or wrong type
     * @throws \JardisSupport\Auth\Exception\TokenExpiredException
     * @throws \JardisSupport\Auth\Exception\TokenRevokedException
     */
    public function redeem(string $plain, TokenType $expected): HashedTokenInterface
    {
        return ($this->redeemToken)($plain, $expected);
    }
}
