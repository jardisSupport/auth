<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Handler\Authentication;

use JardisSupport\Auth\Data\HashedToken;
use JardisSupport\Auth\Data\TenantAuthResult;
use JardisSupport\Auth\Exception\TokenExpiredException;
use JardisSupport\Auth\Exception\TokenRevokedException;
use JardisSupport\Auth\Handler\Token\VerifyToken;
use JardisSupport\Contract\Auth\CredentialInterface;
use JardisSupport\Contract\Auth\CredentialType;
use JardisSupport\Contract\Auth\TokenStoreInterface;
use JardisSupport\Contract\Auth\TokenType;

/** Resolves a token credential to subject, tenant and session reference: lookup, verification, claim extraction. */
final class AuthenticateToken
{
    public function __construct(
        private readonly TokenStoreInterface $tokenStore,
        private readonly VerifyToken $verifyToken,
        private readonly string $tenantClaim,
        private readonly TokenType $expectedType,
    ) {
    }

    public function __invoke(CredentialInterface $credential): TenantAuthResult
    {
        if ($credential->getType() !== CredentialType::Token) {
            return TenantAuthResult::failure('Unsupported credential type');
        }

        $plainToken = $credential->getValue();
        $reference = HashedToken::hashOf($plainToken);
        $stored = $this->tokenStore->find($reference);

        if ($stored === null) {
            return TenantAuthResult::failure('Invalid token');
        }

        try {
            $verified = ($this->verifyToken)($plainToken, $stored, $this->expectedType);
        } catch (TokenExpiredException) {
            return TenantAuthResult::failure('Token expired');
        } catch (TokenRevokedException) {
            return TenantAuthResult::failure('Token revoked');
        }

        $subject = $stored->getSubject();

        if (!$verified || $subject === null) {
            return TenantAuthResult::failure('Invalid token');
        }

        $tenant = $stored->getClaims()[$this->tenantClaim] ?? null;

        return TenantAuthResult::success(
            $subject,
            is_string($tenant) && $tenant !== '' ? $tenant : null,
            $reference,
        );
    }
}
