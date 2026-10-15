<?php

declare(strict_types=1);

namespace JardisSupport\Auth;

use JardisSupport\Contract\Auth\AuthServicesInterface;
use JardisSupport\Contract\Auth\PasswordHasherInterface;
use JardisSupport\Contract\Auth\SessionManagerInterface;
use JardisSupport\Contract\Auth\TokenIssuerInterface;
use JardisSupport\Contract\Auth\TokenRedeemerInterface;
use JardisSupport\Contract\Auth\TokenStoreInterface;

/**
 * Bundle of the four auth services a kernel wires: sessions, token issuer, token redeemer and password hasher.
 * Holds ready-made services only — it reads no environment; key and store come from the caller.
 */
final class AuthServices implements AuthServicesInterface
{
    public function __construct(
        private readonly SessionManagerInterface $sessions,
        private readonly TokenIssuerInterface $tokenIssuer,
        private readonly TokenRedeemerInterface $tokenRedeemer,
        private readonly PasswordHasherInterface $hasher,
    ) {
    }

    /**
     * Builds the bundle over one token store with the package defaults (TTLs, token length, Argon2id hasher
     * unless one is given).
     *
     * @param string $accessTokenKey raw 32-byte signing key; rotating it invalidates every issued access token
     */
    public static function fromStore(
        TokenStoreInterface $store,
        #[\SensitiveParameter] string $accessTokenKey,
        ?PasswordHasherInterface $hasher = null,
    ): self {
        return new self(
            new SessionManager($store, $accessTokenKey),
            new TokenIssuer($store),
            new TokenRedeemer($store),
            $hasher ?? PasswordHasher::argon2id(),
        );
    }

    public function sessions(): SessionManagerInterface
    {
        return $this->sessions;
    }

    public function tokenIssuer(): TokenIssuerInterface
    {
        return $this->tokenIssuer;
    }

    public function tokenRedeemer(): TokenRedeemerInterface
    {
        return $this->tokenRedeemer;
    }

    public function hasher(): PasswordHasherInterface
    {
        return $this->hasher;
    }
}
