<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Tests\Integration;

use DateTimeImmutable;
use JardisSupport\Auth\Data\Session;
use JardisSupport\Auth\Handler\Token\VerifyAccessToken;
use JardisSupport\Auth\SessionManager;
use JardisSupport\Auth\Tests\Support\InMemoryTokenStore;
use JardisSupport\Contract\Auth\SessionInterface;
use PHPUnit\Framework\TestCase;

/**
 * A consumer reads the session expiry through the SessionInterface contract, never from the implementation class.
 */
final class SessionExpiryContractTest extends TestCase
{
    private const KEY = 'kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk';
    private const ACCESS_TTL = 3600;

    public function testCreatedSessionExposesItsExpiryThroughTheContract(): void
    {
        // Arrange
        $manager = new SessionManager(
            tokenStore: new InMemoryTokenStore(),
            accessTokenKey: self::KEY,
            accessTokenTtl: self::ACCESS_TTL,
        );
        $before = time();

        // Act
        $session = $manager->create('user:42')->getSession();
        $after = time();

        // Assert - read through the contract type only
        self::assertInstanceOf(SessionInterface::class, $session);
        $expiresAt = $session->getExpiresAt();
        self::assertInstanceOf(DateTimeImmutable::class, $expiresAt);
        self::assertGreaterThanOrEqual($before + self::ACCESS_TTL, $expiresAt->getTimestamp());
        self::assertLessThanOrEqual($after + self::ACCESS_TTL, $expiresAt->getTimestamp());
    }

    public function testExpiryEqualsTheExpiryOfTheSignedAccessToken(): void
    {
        // Arrange
        $manager = new SessionManager(
            tokenStore: new InMemoryTokenStore(),
            accessTokenKey: self::KEY,
            accessTokenTtl: self::ACCESS_TTL,
        );

        // Act
        $result = $manager->create('user:42');
        $payload = (new VerifyAccessToken(self::KEY))($result->getAccessToken());

        // Assert
        self::assertIsArray($payload);
        self::assertSame($payload['exp'], $result->getSession()->getExpiresAt()?->getTimestamp());
    }

    public function testSessionWithoutExpiryReturnsNull(): void
    {
        // Arrange
        $session = new Session(
            subject: 'user:42',
            tokenHash: 'hash',
            createdAt: new DateTimeImmutable(),
            expiresAt: null,
        );

        // Act
        $contract = $session;

        // Assert
        self::assertNull($contract->getExpiresAt());
        self::assertFalse($contract->isExpired());
    }

    public function testSessionWithExpiryReturnsTheStoredValue(): void
    {
        // Arrange
        $expiresAt = new DateTimeImmutable('2030-01-01 12:00:00');
        $session = new Session(
            subject: 'user:42',
            tokenHash: 'hash',
            createdAt: new DateTimeImmutable('2029-01-01'),
            expiresAt: $expiresAt,
        );

        // Act / Assert
        self::assertSame($expiresAt, $session->getExpiresAt());
        self::assertSame($expiresAt, $session->expiresAt);
    }
}
