<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Tests\Integration\Support;

use DateTimeImmutable;
use JardisSupport\Auth\Tests\Support\InMemoryTokenStore;
use JardisSupport\Auth\Data\HashedToken;
use JardisSupport\Contract\Auth\TokenType;
use PHPUnit\Framework\TestCase;

final class InMemoryTokenStoreTest extends TestCase
{
    private InMemoryTokenStore $store;

    protected function setUp(): void
    {
        $this->store = new InMemoryTokenStore();
    }

    private function buildToken(
        string $hash,
        string $subject = 'user:1',
        ?DateTimeImmutable $expiresAt = null,
        bool $revoked = false,
    ): HashedToken {
        return new HashedToken(
            hash: $hash,
            type: TokenType::Access,
            subject: $subject,
            claims: [],
            expiresAt: $expiresAt,
            createdAt: new DateTimeImmutable(),
            revoked: $revoked,
        );
    }

    public function testStoreAndFindReturnsStoredToken(): void
    {
        // Arrange
        $token = $this->buildToken('abc123');

        // Act
        $this->store->store($token);
        $found = $this->store->find('abc123');

        // Assert
        self::assertNotNull($found);
        self::assertSame('abc123', $found->hash);
        self::assertSame('user:1', $found->subject);
    }

    public function testFindWithUnknownHashReturnsNull(): void
    {
        // Arrange (Store ist leer)

        // Act
        $result = $this->store->find('nonexistent-hash');

        // Assert
        self::assertNull($result);
    }

    public function testRevokeMarksTokenAsRevoked(): void
    {
        // Arrange
        $token = $this->buildToken('token-hash-1');
        $this->store->store($token);

        // Act
        $this->store->revoke('token-hash-1');

        // Assert
        $found = $this->store->find('token-hash-1');
        self::assertNotNull($found);
        self::assertTrue($found->revoked);
    }

    public function testRevokeForUnknownHashDoesNothing(): void
    {
        // Arrange (kein Token im Store)

        // Act (darf nicht werfen)
        $this->store->revoke('does-not-exist');

        // Assert
        self::assertNull($this->store->find('does-not-exist'));
    }

    public function testRevokeAllForSubjectRevokesAllMatchingTokens(): void
    {
        // Arrange
        $token1 = $this->buildToken('hash-1', 'user:42');
        $token2 = $this->buildToken('hash-2', 'user:42');
        $token3 = $this->buildToken('hash-3', 'user:99');

        $this->store->store($token1);
        $this->store->store($token2);
        $this->store->store($token3);

        // Act
        $this->store->revokeAllForSubject('user:42');

        // Assert
        $found1 = $this->store->find('hash-1');
        $found2 = $this->store->find('hash-2');
        $found3 = $this->store->find('hash-3');

        self::assertNotNull($found1);
        self::assertNotNull($found2);
        self::assertNotNull($found3);

        self::assertTrue($found1->revoked);
        self::assertTrue($found2->revoked);
        self::assertFalse($found3->revoked);
    }

    public function testDeleteExpiredRemovesExpiredTokensAndReturnsCount(): void
    {
        // Arrange
        $expired1 = $this->buildToken('expired-1', expiresAt: new DateTimeImmutable('-1 hour'));
        $expired2 = $this->buildToken('expired-2', expiresAt: new DateTimeImmutable('-2 minutes'));
        $valid = $this->buildToken('valid-1', expiresAt: new DateTimeImmutable('+1 hour'));
        $noExpiry = $this->buildToken('no-expiry');

        $this->store->store($expired1);
        $this->store->store($expired2);
        $this->store->store($valid);
        $this->store->store($noExpiry);

        // Act
        $count = $this->store->deleteExpired();

        // Assert
        self::assertSame(2, $count);
        self::assertNull($this->store->find('expired-1'));
        self::assertNull($this->store->find('expired-2'));
        self::assertNotNull($this->store->find('valid-1'));
        self::assertNotNull($this->store->find('no-expiry'));
    }

    public function testDeleteExpiredWhenNoneExpiredReturnsZero(): void
    {
        // Arrange
        $valid = $this->buildToken('valid-1', expiresAt: new DateTimeImmutable('+1 hour'));
        $this->store->store($valid);

        // Act
        $count = $this->store->deleteExpired();

        // Assert
        self::assertSame(0, $count);
        self::assertNotNull($this->store->find('valid-1'));
    }

    public function testDeleteExpiredOnEmptyStoreReturnsZero(): void
    {
        // Arrange (Store ist leer)

        // Act
        $count = $this->store->deleteExpired();

        // Assert
        self::assertSame(0, $count);
    }

    public function testStoreOverwritesExistingTokenWithSameHash(): void
    {
        // Arrange
        $original = $this->buildToken('same-hash', 'user:1');
        $replacement = $this->buildToken('same-hash', 'user:2');

        $this->store->store($original);

        // Act
        $this->store->store($replacement);

        // Assert
        $found = $this->store->find('same-hash');
        self::assertNotNull($found);
        self::assertSame('user:2', $found->subject);
    }
}
