<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Handler\Token;

use JardisSupport\Auth\Data\IssuedToken;
use JardisSupport\Auth\Data\Subject;
use JardisSupport\Auth\Data\Token;
use JardisSupport\Contract\Auth\TokenStoreInterface;
use JardisSupport\Contract\Auth\TokenType;

/** Creates a token of a given type for a subject and stores only its hash. */
final class IssueToken
{
    /**
     * @param positive-int $tokenLength
     */
    public function __construct(
        private readonly TokenStoreInterface $tokenStore,
        private readonly int $tokenLength,
    ) {
    }

    /**
     * @param positive-int $ttlSeconds
     * @param array<string, mixed> $claims
     */
    public function __invoke(TokenType $type, Subject|string $subject, int $ttlSeconds, array $claims = []): IssuedToken
    {
        $subject = is_string($subject) ? Subject::parse($subject) : $subject;

        $token = Token::create($type, $this->tokenLength)
            ->forSubject($subject->toString())
            ->expiresIn($ttlSeconds)
            ->withClaims($claims);

        $hashed = $token->hash();
        $this->tokenStore->store($hashed);

        return new IssuedToken($token->value, $hashed);
    }
}
