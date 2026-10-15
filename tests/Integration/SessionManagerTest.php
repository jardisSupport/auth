<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Tests\Integration;

use JardisSupport\Auth\Data\Event\AllSessionsInvalidated;
use JardisSupport\Auth\Data\Event\SessionCreated;
use JardisSupport\Auth\Data\Event\SessionInvalidated;
use JardisSupport\Auth\Data\Event\SessionRefreshed;
use JardisSupport\Auth\Handler\Session\InvalidateAllSessions;
use JardisSupport\Auth\Data\Session;
use JardisSupport\Auth\Data\SessionResult;
use JardisSupport\Auth\Data\Subject;
use JardisSupport\Auth\Exception\AuthenticationException;
use JardisSupport\Auth\SessionManager;
use JardisSupport\Auth\Tests\Support\InMemoryTokenStore;
use PHPUnit\Framework\TestCase;

final class SessionManagerTest extends TestCase
{
    private InMemoryTokenStore $tokenStore;
    private SessionManager $sessionManager;

    protected function setUp(): void
    {
        $this->tokenStore = new InMemoryTokenStore();
        $this->sessionManager = new SessionManager(
            tokenStore: $this->tokenStore,
            accessTokenKey: str_repeat('k', 32),
            accessTokenTtl: 3600,
            refreshTokenTtl: 604800,
        );
    }

    public function testCreateReturnsSessionResult(): void
    {
        // Arrange
        $subject = Subject::from('42', 'user');

        // Act
        $result = $this->sessionManager->create($subject);

        // Assert
        self::assertInstanceOf(SessionResult::class, $result);
        self::assertInstanceOf(Session::class, $result->session);
        self::assertNotEmpty($result->accessToken);
        self::assertNotEmpty($result->refreshToken);
    }

    public function testCreateStoresOnlyTheRefreshTokenInStore(): void
    {
        // Arrange
        $subject = Subject::from('42', 'user');

        // Act
        $result = $this->sessionManager->create($subject);

        // Assert
        $refreshHash = hash('sha256', $result->refreshToken);

        self::assertNull($this->tokenStore->find(hash('sha256', $result->accessToken)));
        self::assertNotNull($this->tokenStore->find($refreshHash));
        self::assertSame($refreshHash, $result->session->tokenHash);
    }

    public function testCreateWithClaimsSetsMetadataOnSession(): void
    {
        // Arrange
        $subject = Subject::from('42', 'user');
        $claims = ['role' => 'editor', 'tenant' => 'acme'];

        // Act
        $result = $this->sessionManager->create($subject, $claims);

        // Assert
        self::assertSame('editor', $result->session->metadata['role']);
        self::assertSame('acme', $result->session->metadata['tenant']);
    }

    public function testCreateSetsCorrectSubjectOnSession(): void
    {
        // Arrange
        $subject = Subject::from('42', 'user');

        // Act
        $result = $this->sessionManager->create($subject);

        // Assert
        self::assertSame('user:42', $result->session->subject);
    }

    public function testCreateReturnsSessionCreatedEvent(): void
    {
        // Arrange
        $subject = Subject::from('42', 'user');

        // Act
        $result = $this->sessionManager->create($subject);

        // Assert
        self::assertCount(1, $result->events);
        self::assertInstanceOf(SessionCreated::class, $result->events[0]);
        self::assertSame('user:42', $result->events[0]->subject);
        self::assertSame($result->session->tokenHash, $result->events[0]->tokenHash);
    }

    public function testRefreshRotatesTokenAndReturnsSessionResult(): void
    {
        // Arrange
        $subject = Subject::from('42', 'user');
        $created = $this->sessionManager->create($subject);
        $originalRefreshToken = $created->refreshToken;

        // Act
        $refreshed = $this->sessionManager->refresh($originalRefreshToken);

        // Assert
        self::assertInstanceOf(SessionResult::class, $refreshed);
        self::assertInstanceOf(Session::class, $refreshed->session);
        self::assertNotEmpty($refreshed->accessToken);
        self::assertNotEmpty($refreshed->refreshToken);
        self::assertNotSame($originalRefreshToken, $refreshed->refreshToken);
    }

    public function testRefreshRevokesOldRefreshToken(): void
    {
        // Arrange
        $subject = Subject::from('42', 'user');
        $created = $this->sessionManager->create($subject);
        $originalRefreshToken = $created->refreshToken;
        $originalHash = hash('sha256', $originalRefreshToken);

        // Act
        $this->sessionManager->refresh($originalRefreshToken);

        // Assert
        $storedToken = $this->tokenStore->find($originalHash);
        self::assertNotNull($storedToken);
        self::assertTrue($storedToken->revoked);
    }

    public function testRefreshReturnsSessionCreatedAndSessionRefreshedEvents(): void
    {
        // Arrange
        $subject = Subject::from('42', 'user');
        $created = $this->sessionManager->create($subject);

        // Act
        $refreshed = $this->sessionManager->refresh($created->refreshToken);

        // Assert
        self::assertCount(2, $refreshed->events);
        self::assertInstanceOf(SessionCreated::class, $refreshed->events[0]);
        self::assertInstanceOf(SessionRefreshed::class, $refreshed->events[1]);

        $refreshEvent = $refreshed->events[1];
        self::assertSame('user:42', $refreshEvent->subject);
        self::assertSame($refreshed->session->tokenHash, $refreshEvent->newTokenHash);
    }

    public function testRefreshWithInvalidTokenThrowsAuthenticationException(): void
    {
        // Arrange
        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('Invalid refresh token');

        // Act
        $this->sessionManager->refresh('nonexistent-token-value');
    }

    public function testInvalidateRevokesSessionTokenAndReturnsEvent(): void
    {
        // Arrange
        $subject = Subject::from('42', 'user');
        $result = $this->sessionManager->create($subject);
        $session = $result->session;

        // Act
        $event = $this->sessionManager->invalidate($session);

        // Assert
        $storedToken = $this->tokenStore->find($session->tokenHash);
        self::assertNotNull($storedToken);
        self::assertTrue($storedToken->revoked);

        self::assertInstanceOf(SessionInvalidated::class, $event);
        self::assertSame('user:42', $event->subject);
        self::assertSame($session->tokenHash, $event->tokenHash);
    }

    public function testInvalidateAllRevokesAllTokens(): void
    {
        // Arrange
        $subject = Subject::from('42', 'user');
        $resultA = $this->sessionManager->create($subject);
        $resultB = $this->sessionManager->create($subject);

        $refreshHashA = $resultA->session->tokenHash;
        $refreshHashB = $resultB->session->tokenHash;

        // Act
        $this->sessionManager->invalidateAll('user:42');

        // Assert
        self::assertTrue($this->tokenStore->find($refreshHashA)?->revoked);
        self::assertTrue($this->tokenStore->find($refreshHashB)?->revoked);
    }

    public function testInvalidateAllHandlerReturnsTheEvent(): void
    {
        $event = (new InvalidateAllSessions($this->tokenStore))('user:42');

        self::assertInstanceOf(AllSessionsInvalidated::class, $event);
        self::assertSame('user:42', $event->subject);
    }

    public function testInvalidateAllDoesNotRevokeTokensOfOtherSubjects(): void
    {
        // Arrange
        $subjectA = Subject::from('42', 'user');
        $subjectB = Subject::from('99', 'user');

        $resultA = $this->sessionManager->create($subjectA);
        $resultB = $this->sessionManager->create($subjectB);

        // Act
        $this->sessionManager->invalidateAll('user:42');

        // Assert
        $tokenB = $this->tokenStore->find($resultB->session->tokenHash);
        self::assertNotNull($tokenB);
        self::assertFalse($tokenB->revoked);
    }

    public function testInvalidateByReferenceRevokesTheRefreshToken(): void
    {
        // Arrange
        $created = $this->sessionManager->create(Subject::from('42', 'user'));

        // Act
        $this->sessionManager->invalidateByReference($created->session->tokenHash);

        // Assert
        $this->expectException(AuthenticationException::class);
        $this->sessionManager->refresh($created->refreshToken);
    }

    public function testMetadataCarriesNoInternalClaims(): void
    {
        // Arrange / Act
        $created = $this->sessionManager->create(Subject::from('42', 'user'), ['tenant' => 'acme', '_foreign' => 'x']);
        $refreshed = $this->sessionManager->refresh($created->refreshToken);

        // Assert
        self::assertSame(['tenant' => 'acme'], $created->session->metadata);
        foreach (array_keys($refreshed->session->metadata) as $key) {
            self::assertStringStartsNotWith('_', (string) $key);
        }
    }

    public function testRefreshedSessionKeepsTheClaimsOfTheOriginalSession(): void
    {
        // Arrange
        $claims = ['tenant' => 'acme', 'role' => 'admin'];
        $created = $this->sessionManager->create(Subject::from('42', 'user'), $claims);

        // Act
        $refreshed = $this->sessionManager->refresh($created->refreshToken);

        // Assert
        self::assertSame($claims, $refreshed->session->metadata);
    }
}
