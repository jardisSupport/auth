<?php

declare(strict_types=1);

namespace JardisSupport\Auth;

use Closure;
use JardisSupport\Auth\Data\TenantAuthResult;
use JardisSupport\Auth\Handler\Authentication\AuthenticateToken;
use JardisSupport\Auth\Handler\Token\VerifyToken;
use JardisSupport\Contract\Auth\AuthenticatorInterface;
use JardisSupport\Contract\Auth\CredentialInterface;
use JardisSupport\Contract\Auth\SessionClaim;
use JardisSupport\Contract\Auth\TokenStoreInterface;
use JardisSupport\Contract\Auth\TokenType;

/**
 * Orchestrates store-based token authentication: a valid, non-revoked, non-expired stored token resolves to
 * a successful result with subject and tenant; every other token yields a failure with a reason.
 *
 * Meant for stored tokens (`ApiKey`, `Verification`, `PasswordReset`, ...). Since v1.5 the session access
 * tokens issued by `SessionManager` are signed and no longer live in the store — authenticate them with
 * `SignedTokenAuthenticator`.
 *
 * The tenant is read from the token claim named by `$tenantClaim` (set when the session is created).
 */
final class TokenAuthenticator implements AuthenticatorInterface
{
    private readonly Closure $authenticateToken;

    public function __construct(
        TokenStoreInterface $tokenStore,
        VerifyToken $verifyToken = new VerifyToken(),
        string $tenantClaim = SessionClaim::TENANT,
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
