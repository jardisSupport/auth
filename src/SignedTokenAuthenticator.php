<?php

declare(strict_types=1);

namespace JardisSupport\Auth;

use Closure;
use JardisSupport\Auth\Data\TenantAuthResult;
use JardisSupport\Auth\Handler\Authentication\AuthenticateSignedToken;
use JardisSupport\Auth\Handler\Token\VerifyAccessToken;
use JardisSupport\Contract\Auth\AuthenticatorInterface;
use JardisSupport\Contract\Auth\CredentialInterface;
use JardisSupport\Contract\Auth\SessionClaim;

/**
 * Orchestrates authentication of signed access tokens (issued by `SessionManager`): signature and expiry
 * are checked locally, no token store is touched. A valid token resolves to subject, tenant and session
 * reference (`sid` = hash of the refresh token); every other token yields a failure with a reason.
 */
final class SignedTokenAuthenticator implements AuthenticatorInterface
{
    private readonly Closure $authenticateSignedToken;

    /**
     * @param string $accessTokenKey raw 32-byte signing key (same as given to `SessionManager`)
     * @param (Closure(): int)|null $clock unix timestamp source, defaults to `time()`
     */
    public function __construct(
        #[\SensitiveParameter] string $accessTokenKey,
        string $tenantClaim = SessionClaim::TENANT,
        ?Closure $clock = null,
    ) {
        $this->authenticateSignedToken = (new AuthenticateSignedToken(
            new VerifyAccessToken($accessTokenKey, $clock),
            $tenantClaim,
        ))->__invoke(...);
    }

    public function authenticate(CredentialInterface $credential): TenantAuthResult
    {
        return ($this->authenticateSignedToken)($credential);
    }
}
