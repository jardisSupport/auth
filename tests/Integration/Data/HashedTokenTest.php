<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Tests\Integration\Data;

use DateTimeImmutable;
use JardisSupport\Auth\Data\HashedToken;
use JardisSupport\Auth\Data\Token;
use JardisSupport\Contract\Auth\TokenType;
use PHPUnit\Framework\TestCase;

final class HashedTokenTest extends TestCase
{
    // --- HashedToken::fromToken() ---

    public function testFromTokenProducesSha256HashOfTokenValue(): void
    {
        // Arrange
        $token = Token::create(TokenType::Access);

        // Act
        $hashed = HashedToken::fromToken($token);

        // Assert
        $this->assertSame(hash('sha256', $token->value), $hashed->hash);
    }

    public function testFromTokenCopiesTypeFromToken(): void
    {
        // Arrange
        $token = Token::create(TokenType::Refresh);

        // Act
        $hashed = HashedToken::fromToken($token);

        // Assert
        $this->assertSame(TokenType::Refresh, $hashed->type);
    }

    public function testFromTokenCopiesSubjectFromToken(): void
    {
        // Arrange
        $token = Token::create(TokenType::Access)->forSubject('user:99');

        // Act
        $hashed = HashedToken::fromToken($token);

        // Assert
        $this->assertSame('user:99', $hashed->subject);
    }

    public function testFromTokenCopiesClaimsFromToken(): void
    {
        // Arrange
        $token = Token::create(TokenType::Access)->withClaims(['role' => 'editor']);

        // Act
        $hashed = HashedToken::fromToken($token);

        // Assert
        $this->assertSame(['role' => 'editor'], $hashed->claims);
    }

    public function testFromTokenCopiesExpiresAtFromToken(): void
    {
        // Arrange
        $token = Token::create(TokenType::Access)->expiresIn(3600);

        // Act
        $hashed = HashedToken::fromToken($token);

        // Assert
        $this->assertEquals($token->expiresAt, $hashed->expiresAt);
    }

    public function testFromTokenSetsNullExpiresAtWhenTokenHasNoExpiry(): void
    {
        // Arrange
        $token = Token::create(TokenType::Access);

        // Act
        $hashed = HashedToken::fromToken($token);

        // Assert
        $this->assertNull($hashed->expiresAt);
    }

    public function testFromTokenDefaultsRevokedToFalse(): void
    {
        // Arrange
        $token = Token::create(TokenType::Access);

        // Act
        $hashed = HashedToken::fromToken($token);

        // Assert
        $this->assertFalse($hashed->revoked);
    }

    // --- HashedToken::isExpired() ---

    public function testIsExpiredReturnsFalseWhenNoExpirySet(): void
    {
        // Arrange
        $token = Token::create(TokenType::Access);
        $hashed = HashedToken::fromToken($token);

        // Act & Assert
        $this->assertFalse($hashed->isExpired());
    }

    public function testIsExpiredReturnsFalseWhenExpiryIsInFuture(): void
    {
        // Arrange
        $token = Token::create(TokenType::Access)->expiresIn(3600);
        $hashed = HashedToken::fromToken($token);

        // Act & Assert
        $this->assertFalse($hashed->isExpired());
    }

    public function testIsExpiredReturnsTrueWhenExpiryIsInPast(): void
    {
        // Arrange
        $token = Token::create(TokenType::Access)->expiresIn(-1);
        $hashed = HashedToken::fromToken($token);

        // Act & Assert
        $this->assertTrue($hashed->isExpired());
    }

    public function testIsExpiredCanBeCalledDirectlyOnConstructedHashedToken(): void
    {
        // Arrange
        $hashed = new HashedToken(
            hash: hash('sha256', 'somevalue'),
            type: TokenType::ApiKey,
            subject: null,
            claims: [],
            expiresAt: new DateTimeImmutable('-1 hour'),
            createdAt: new DateTimeImmutable('-2 hours'),
        );

        // Act & Assert
        $this->assertTrue($hashed->isExpired());
    }

    // --- HashedToken::withRevoked() ---

    public function testWithRevokedReturnsNewInstanceWithRevokedTrue(): void
    {
        // Arrange
        $token = Token::create(TokenType::Access);
        $hashed = HashedToken::fromToken($token);

        // Act
        $revoked = $hashed->withRevoked();

        // Assert
        $this->assertTrue($revoked->revoked);
    }

    public function testWithRevokedDoesNotMutateOriginalHashedToken(): void
    {
        // Arrange
        $token = Token::create(TokenType::Access);
        $hashed = HashedToken::fromToken($token);

        // Act
        $hashed->withRevoked();

        // Assert
        $this->assertFalse($hashed->revoked);
    }

    public function testWithRevokedPreservesHash(): void
    {
        // Arrange
        $token = Token::create(TokenType::Access);
        $hashed = HashedToken::fromToken($token);

        // Act
        $revoked = $hashed->withRevoked();

        // Assert
        $this->assertSame($hashed->hash, $revoked->hash);
    }

    public function testWithRevokedPreservesAllOtherFields(): void
    {
        // Arrange
        $token = Token::create(TokenType::Refresh)
            ->forSubject('user:5')
            ->withClaims(['scope' => 'read'])
            ->expiresIn(600);
        $hashed = HashedToken::fromToken($token);

        // Act
        $revoked = $hashed->withRevoked();

        // Assert
        $this->assertSame($hashed->type, $revoked->type);
        $this->assertSame($hashed->subject, $revoked->subject);
        $this->assertSame($hashed->claims, $revoked->claims);
        $this->assertEquals($hashed->expiresAt, $revoked->expiresAt);
        $this->assertEquals($hashed->createdAt, $revoked->createdAt);
    }
}
