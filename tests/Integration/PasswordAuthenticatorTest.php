<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Tests\Integration;

use JardisSupport\Auth\Data\AuthenticationResult;
use JardisSupport\Auth\Data\Credential;
use JardisSupport\Auth\Data\Event\AuthenticationFailed;
use JardisSupport\Auth\Data\Event\AuthenticationSucceeded;
use JardisSupport\Auth\Data\Event\SessionCreated;
use JardisSupport\Auth\Data\Subject;
use JardisSupport\Auth\PasswordAuthenticator;
use JardisSupport\Auth\PasswordHasher;
use JardisSupport\Auth\SessionManager;
use JardisSupport\Auth\Tests\Support\InMemoryTokenStore;
use JardisSupport\Contract\Auth\AuthResultInterface;
use JardisSupport\Contract\Auth\CredentialType;
use PHPUnit\Framework\TestCase;

final class PasswordAuthenticatorTest extends TestCase
{
    private PasswordHasher $hasher;
    private SessionManager $sessionManager;
    private string $hashedPassword;

    protected function setUp(): void
    {
        $this->hasher = PasswordHasher::bcrypt(4);
        $this->hashedPassword = $this->hasher->hash('secret123');

        $tokenStore = new InMemoryTokenStore();
        $this->sessionManager = new SessionManager(
            tokenStore: $tokenStore,
            accessTokenTtl: 3600,
            refreshTokenTtl: 604800,
        );
    }

    private function buildAuthenticator(?array $userData = null): PasswordAuthenticator
    {
        $userLookup = function (string $identifier) use ($userData): ?array {
            if ($userData !== null && $identifier === $userData['identifier']) {
                return [
                    'hash' => $userData['hash'],
                    'subject' => $userData['subject'],
                    'claims' => $userData['claims'] ?? [],
                ];
            }

            return null;
        };

        return new PasswordAuthenticator(
            $this->hasher,
            $this->sessionManager,
            $userLookup,
        );
    }

    public function testAuthenticateWithValidCredentialsReturnsSuccess(): void
    {
        // Arrange
        $authenticator = $this->buildAuthenticator([
            'identifier' => 'john@example.com',
            'hash' => $this->hashedPassword,
            'subject' => Subject::from('42', 'user'),
            'claims' => ['role' => 'editor'],
        ]);
        $credential = Credential::password('john@example.com', 'secret123');

        // Act
        $result = $authenticator->authenticate($credential);

        // Assert
        self::assertInstanceOf(AuthenticationResult::class, $result);
        self::assertTrue($result->isSuccess());
        self::assertSame('user:42', $result->getSubject());
        self::assertNull($result->getReason());
        self::assertNotNull($result->session);
        self::assertNotNull($result->accessToken);
        self::assertNotNull($result->refreshToken);
    }

    public function testAuthenticateWithValidCredentialsReturnsEvents(): void
    {
        // Arrange
        $authenticator = $this->buildAuthenticator([
            'identifier' => 'john@example.com',
            'hash' => $this->hashedPassword,
            'subject' => Subject::from('42', 'user'),
        ]);
        $credential = Credential::password('john@example.com', 'secret123');

        // Act
        $result = $authenticator->authenticate($credential);

        // Assert — SessionCreated from SessionManager + AuthenticationSucceeded
        self::assertCount(2, $result->events);
        self::assertInstanceOf(SessionCreated::class, $result->events[0]);
        self::assertInstanceOf(AuthenticationSucceeded::class, $result->events[1]);
        self::assertSame('user:42', $result->events[1]->subject);
    }

    public function testAuthenticateWithUnknownUserReturnsFailure(): void
    {
        // Arrange
        $authenticator = $this->buildAuthenticator(null);
        $credential = Credential::password('unknown@example.com', 'secret123');

        // Act
        $result = $authenticator->authenticate($credential);

        // Assert
        self::assertInstanceOf(AuthenticationResult::class, $result);
        self::assertFalse($result->isSuccess());
        self::assertSame('Invalid credentials', $result->getReason());
        self::assertNull($result->session);
        self::assertNull($result->accessToken);
        self::assertNull($result->refreshToken);
    }

    public function testAuthenticateWithUnknownUserReturnsAuthenticationFailedEvent(): void
    {
        // Arrange
        $authenticator = $this->buildAuthenticator(null);
        $credential = Credential::password('unknown@example.com', 'secret123');

        // Act
        $result = $authenticator->authenticate($credential);

        // Assert
        self::assertCount(1, $result->events);
        self::assertInstanceOf(AuthenticationFailed::class, $result->events[0]);
        self::assertSame(CredentialType::Password, $result->events[0]->credentialType);
        self::assertSame('User not found', $result->events[0]->reason);
    }

    public function testAuthenticateWithWrongPasswordReturnsFailure(): void
    {
        // Arrange
        $authenticator = $this->buildAuthenticator([
            'identifier' => 'john@example.com',
            'hash' => $this->hashedPassword,
            'subject' => Subject::from('42', 'user'),
        ]);
        $credential = Credential::password('john@example.com', 'wrong-password');

        // Act
        $result = $authenticator->authenticate($credential);

        // Assert
        self::assertFalse($result->isSuccess());
        self::assertSame('Invalid credentials', $result->getReason());
        self::assertNull($result->session);
    }

    public function testAuthenticateWithWrongPasswordReturnsAuthenticationFailedEvent(): void
    {
        // Arrange
        $authenticator = $this->buildAuthenticator([
            'identifier' => 'john@example.com',
            'hash' => $this->hashedPassword,
            'subject' => Subject::from('42', 'user'),
        ]);
        $credential = Credential::password('john@example.com', 'wrong-password');

        // Act
        $result = $authenticator->authenticate($credential);

        // Assert
        self::assertCount(1, $result->events);
        self::assertInstanceOf(AuthenticationFailed::class, $result->events[0]);
        self::assertSame('Invalid password', $result->events[0]->reason);
    }

    public function testAuthenticateWithUnsupportedCredentialTypeReturnsFailure(): void
    {
        // Arrange
        $authenticator = $this->buildAuthenticator(null);
        $credential = Credential::apiKey('key-id', 'api-key-value');

        // Act
        $result = $authenticator->authenticate($credential);

        // Assert
        self::assertFalse($result->isSuccess());
        self::assertSame('Unsupported credential type', $result->getReason());
    }

    public function testAuthenticateWithUnsupportedCredentialTypeReturnsAuthenticationFailedEvent(): void
    {
        // Arrange
        $authenticator = $this->buildAuthenticator(null);
        $credential = Credential::apiKey('key-id', 'api-key-value');

        // Act
        $result = $authenticator->authenticate($credential);

        // Assert
        self::assertCount(1, $result->events);
        self::assertInstanceOf(AuthenticationFailed::class, $result->events[0]);
        self::assertSame(CredentialType::ApiKey, $result->events[0]->credentialType);
        self::assertSame('Unsupported credential type', $result->events[0]->reason);
    }

    public function testAuthenticateWithValidCredentialsCreatesSessionWithClaims(): void
    {
        // Arrange
        $authenticator = $this->buildAuthenticator([
            'identifier' => 'john@example.com',
            'hash' => $this->hashedPassword,
            'subject' => Subject::from('42', 'user'),
            'claims' => ['role' => 'admin', 'tenant' => 'acme'],
        ]);
        $credential = Credential::password('john@example.com', 'secret123');

        // Act
        $result = $authenticator->authenticate($credential);

        // Assert
        self::assertSame('user:42', $result->session->subject);
        self::assertSame('admin', $result->session->metadata['role']);
        self::assertSame('acme', $result->session->metadata['tenant']);
    }

    public function testAuthenticateReturnsAuthResultInterfaceImplementation(): void
    {
        // Arrange
        $authenticator = $this->buildAuthenticator([
            'identifier' => 'john@example.com',
            'hash' => $this->hashedPassword,
            'subject' => Subject::from('42', 'user'),
        ]);
        $credential = Credential::password('john@example.com', 'secret123');

        // Act
        $result = $authenticator->authenticate($credential);

        // Assert
        self::assertInstanceOf(AuthResultInterface::class, $result);
    }
}
