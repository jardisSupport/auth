<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Handler\Authentication;

use JardisSupport\Auth\Data\TenantAuthResult;
use JardisSupport\Auth\Exception\TokenExpiredException;
use JardisSupport\Auth\Handler\Token\VerifyAccessToken;
use JardisSupport\Contract\Auth\CredentialInterface;
use JardisSupport\Contract\Auth\CredentialType;
use JardisSupport\Contract\Auth\SessionClaim;

/** Resolves a signed access token to subject, tenant and session reference (`sid`) — no store lookup. */
final class AuthenticateSignedToken
{
    public function __construct(
        private readonly VerifyAccessToken $verifyAccessToken,
        private readonly string $tenantClaim,
    ) {
    }

    public function __invoke(CredentialInterface $credential): TenantAuthResult
    {
        if ($credential->getType() !== CredentialType::Token) {
            return TenantAuthResult::failure('Unsupported credential type');
        }

        try {
            $payload = ($this->verifyAccessToken)($credential->getValue());
        } catch (TokenExpiredException) {
            return TenantAuthResult::failure('Token expired');
        }

        if ($payload === null) {
            return TenantAuthResult::failure('Invalid token');
        }

        $subject = $payload['sub'] ?? null;
        $sid = $payload['sid'] ?? null;
        $claims = $payload['claims'] ?? [];

        if (!is_string($subject) || $subject === '' || !is_string($sid) || !is_array($claims)) {
            return TenantAuthResult::failure('Invalid token');
        }

        $tenant = $claims[$this->tenantClaim] ?? null;

        $role = $claims[SessionClaim::ROLE] ?? null;

        return TenantAuthResult::success(
            $subject,
            is_string($tenant) && $tenant !== '' ? $tenant : null,
            $sid,
            is_string($role) && $role !== '' ? $role : null,
        );
    }
}
