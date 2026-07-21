<?php

declare(strict_types=1);

namespace JardisSupport\Auth;

use Closure;
use DateTimeImmutable;
use JardisSupport\Auth\Data\AuthenticationResult;
use JardisSupport\Auth\Data\AuthResult;
use JardisSupport\Auth\Data\Event\AuthenticationFailed;
use JardisSupport\Auth\Data\Event\AuthenticationSucceeded;
use JardisSupport\Auth\Data\Subject;
use JardisSupport\Auth\Handler\Authentication\BuildAuthResult;
use JardisSupport\Auth\Handler\Authentication\LookupUser;
use JardisSupport\Auth\Handler\Authentication\VerifyCredential;
use JardisSupport\Contract\Auth\AuthenticatorInterface;
use JardisSupport\Contract\Auth\CredentialInterface;
use JardisSupport\Contract\Auth\CredentialType;

/** Orchestrates password-based authentication: user lookup, credential verification, and session creation. */
final class PasswordAuthenticator implements AuthenticatorInterface
{
    private readonly Closure $lookupUser;
    private readonly Closure $verifyCredential;
    private readonly Closure $buildAuthResult;

    /**
     * @param Closure(string): ?array{hash: string, subject: Subject, claims?: array<string, mixed>} $userLookup
     */
    public function __construct(
        PasswordHasher $passwordHasher,
        private readonly SessionManager $sessionManager,
        Closure $userLookup,
    ) {
        $this->lookupUser = (new LookupUser($userLookup))->__invoke(...);
        $this->verifyCredential = (new VerifyCredential($passwordHasher->verify(...)))->__invoke(...);
        $this->buildAuthResult = (new BuildAuthResult())->__invoke(...);
    }

    public function authenticate(CredentialInterface $credential): AuthenticationResult
    {
        if ($credential->getType() !== CredentialType::Password) {
            return ($this->buildAuthResult)(
                AuthResult::failure('Unsupported credential type'),
                null,
                [new AuthenticationFailed(
                    credentialType: $credential->getType(),
                    reason: 'Unsupported credential type',
                    timestamp: new DateTimeImmutable(),
                )],
            );
        }

        $userData = ($this->lookupUser)($credential->getIdentifier());

        if ($userData === null) {
            return ($this->buildAuthResult)(
                AuthResult::failure('Invalid credentials'),
                null,
                [new AuthenticationFailed(
                    credentialType: CredentialType::Password,
                    reason: 'User not found',
                    timestamp: new DateTimeImmutable(),
                )],
            );
        }

        if (!($this->verifyCredential)($credential->getValue(), $userData['hash'])) {
            return ($this->buildAuthResult)(
                AuthResult::failure('Invalid credentials'),
                null,
                [new AuthenticationFailed(
                    credentialType: CredentialType::Password,
                    reason: 'Invalid password',
                    timestamp: new DateTimeImmutable(),
                )],
            );
        }

        $sessionResult = $this->sessionManager->create(
            $userData['subject'],
            $userData['claims'] ?? [],
        );

        return ($this->buildAuthResult)(
            AuthResult::success($userData['subject']),
            $sessionResult,
            [new AuthenticationSucceeded(
                subject: $userData['subject']->toString(),
                timestamp: new DateTimeImmutable(),
            )],
        );
    }
}
