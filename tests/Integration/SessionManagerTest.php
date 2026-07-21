<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Tests\Integration;

use JardisSupport\Auth\Data\Event\AllSessionsInvalidated;
use JardisSupport\Auth\Data\Event\SessionCreated;
use JardisSupport\Auth\Data\Event\SessionInvalidated;
use JardisSupport\Auth\Data\Event\SessionRefreshed;
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

    public function testCreateStoresBothTokensInStore(): void
    {
        // Arrange
        $subject = Subject::from('42', 'user');

        // Act
        $result = $this->sessionManager->create($subject);

        // Assert
        $accessHash = hash('sha256', $result->accessToken);
        $refreshHash = hash('sha256', $result->refreshToken);

        self::assertNotNull($this->tokenStore->find($accessHash));
        self::assertNotNull($this->tokenStore->find($refreshHash));
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

    public function testInvalidateAllRevokesAllTokensAndReturnsEvent(): void
    {
        // Arrange
        $subject = Subject::from('42', 'user');
        $resultA = $this->sessionManager->create($subject);
        $resultB = $this->sessionManager->create($subject);

        $accessHashA = $resultA->session->tokenHash;
        $accessHashB = $resultB->session->tokenHash;
        $refreshHashA = hash('sha256', $resultA->refreshToken);
        $refreshHashB = hash('sha256', $resultB->refreshToken);

        // Act
        $event = $this->sessionManager->invalidateAll('user:42');

        // Assert
        $tokenAA = $this->tokenStore->find($accessHashA);
        $tokenAB = $this->tokenStore->find($accessHashB);
        $tokenRA = $this->tokenStore->find($refreshHashA);
        $tokenRB = $this->tokenStore->find($refreshHashB);

        self::assertNotNull($tokenAA);
        self::assertNotNull($tokenAB);
        self::assertNotNull($tokenRA);
        self::assertNotNull($tokenRB);

        self::assertTrue($tokenAA->revoked);
        self::assertTrue($tokenAB->revoked);
        self::assertTrue($tokenRA->revoked);
        self::assertTrue($tokenRB->revoked);

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
}
