<?php

declare(strict_types=1);

namespace JardisSupport\Auth;

use Closure;
use JardisSupport\Auth\Data\IssuedToken;
use JardisSupport\Auth\Data\Subject;
use JardisSupport\Auth\Handler\Token\IssueToken;
use JardisSupport\Contract\Auth\TokenStoreInterface;
use JardisSupport\Contract\Auth\TokenType;

/**
 * Orchestrates issuing of one-time tokens (invitation, password reset, verification):
 * the plain value is returned once, only its hash is stored.
 */
final class TokenIssuer
{
    private readonly Closure $issueToken;

    /**
     * @param positive-int $tokenLength
     */
    public function __construct(
        TokenStoreInterface $tokenStore,
        int $tokenLength = 32,
    ) {
        $this->issueToken = (new IssueToken($tokenStore, $tokenLength))->__invoke(...);
    }

    /**
     * @param positive-int $ttlSeconds
     * @param array<string, mixed> $claims
     */
    public function issue(TokenType $type, Subject $subject, int $ttlSeconds, array $claims = []): IssuedToken
    {
        return ($this->issueToken)($type, $subject, $ttlSeconds, $claims);
    }
}
