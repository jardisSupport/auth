<?php

declare(strict_types=1);

namespace JardisSupport\Auth;

use Closure;
use JardisSupport\Auth\Data\TenantAuthResult;
use JardisSupport\Auth\Handler\Authentication\AuthenticateToken;
use JardisSupport\Auth\Handler\Token\VerifyToken;
use JardisSupport\Contract\Auth\AuthenticatorInterface;
use JardisSupport\Contract\Auth\CredentialInterface;
use JardisSupport\Contract\Auth\TokenStoreInterface;
use JardisSupport\Contract\Auth\TokenType;

/**
 * Orchestrates token authentication: a valid, non-revoked, non-expired access token resolves to a
 * successful result with subject and tenant; every other token yields a failure with a reason.
 *
 * The tenant is read from the token claim named by `$tenantClaim` (set when the session is created).
 */
final class TokenAuthenticator implements AuthenticatorInterface
{
    private readonly Closure $authenticateToken;

    public function __construct(
        TokenStoreInterface $tokenStore,
        VerifyToken $verifyToken = new VerifyToken(),
        string $tenantClaim = 'tenant',
        TokenType $expectedType = TokenType::Access,
    ) {
        $this->authenticateToken = (new AuthenticateToken(
            $tokenStore,
            $verifyToken,
            $tenantClaim,
            $expectedType,
        ))->__invoke(...);
    }

    public function authenticate(CredentialInterface $credential): TenantAuthResult
    {
        return ($this->authenticateToken)($credential);
    }
}
