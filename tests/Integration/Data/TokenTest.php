<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Tests\Integration\Data;

use DateTimeImmutable;
use JardisSupport\Auth\Data\HashedToken;
use JardisSupport\Auth\Data\Token;
use JardisSupport\Contract\Auth\TokenType;
use PHPUnit\Framework\TestCase;

final class TokenTest extends TestCase
{
    // --- Token::create() ---

    public function testCreateReturnsTokenWithExpectedType(): void
    {
        // Arrange
        $type = TokenType::Access;

        // Act
        $token = Token::create($type);

        // Assert
        $this->assertSame($type, $token->type);
    }

    public function testCreateReturnsTokenWithHexValue(): void
    {
        // Arrange & Act
        $token = Token::create(TokenType::Access);

        // Assert
        $this->assertMatchesRegularExpression('/^[0-9a-f]+$/', $token->value);
    }

    public function testCreateReturnsTokenWithDefaultLength64HexChars(): void
    {
        // Arrange & Act
        $token = Token::create(TokenType::Access); // default length=32 → 64 hex chars

        // Assert
        $this->assertSame(64, strlen($token->value));
    }

    public function testCreateReturnsTokenWithCustomLength(): void
    {
        // Arrange & Act
        $token = Token::create(TokenType::ApiKey, length: 16); // 16 bytes → 32 hex chars

        // Assert
        $this->assertSame(32, strlen($token->value));
    }

    public function testCreateReturnsTokenWithNullSubject(): void
    {
        // Arrange & Act
        $token = Token::create(TokenType::Refresh);

        // Assert
        $this->assertNull($token->subject);
    }

    public function testCreateReturnsTokenWithEmptyClaims(): void
    {
        // Arrange & Act
        $token = Token::create(TokenType::Refresh);

        // Assert
        $this->assertSame([], $token->claims);
    }

    public function testCreateReturnsTokenWithNullExpiresAt(): void
    {
        // Arrange & Act
        $token = Token::create(TokenType::Verification);

        // Assert
        $this->assertNull($token->expiresAt);
    }

    public function testCreateReturnsDifferentTokensOnEachCall(): void
    {
        // Arrange & Act
        $token1 = Token::create(TokenType::Access);
        $token2 = Token::create(TokenType::Access);

        // Assert
        $this->assertNotSame($token1->value, $token2->value);
    }

    // --- Token::expiresIn() ---

    public function testExpiresInReturnsNewTokenWithExpiresAt(): void
    {
        // Arrange
        $token = Token::create(TokenType::Access);

        // Act
        $withExpiry = $token->expiresIn(3600);

        // Assert
        $this->assertNotNull($withExpiry->expiresAt);
    }

    public function testExpiresInDoesNotMutateOriginalToken(): void
    {
        // Arrange
        $token = Token::create(TokenType::Access);

        // Act
        $token->expiresIn(3600);

        // Assert
        $this->assertNull($token->expiresAt);
    }

    public function testExpiresInSetsExpiryRelativeToCreatedAt(): void
    {
        // Arrange
        $token = Token::create(TokenType::Access);

        // Act
        $withExpiry = $token->expiresIn(60);

        // Assert
        $expected = $token->createdAt->modify('+60 seconds');
        $this->assertEquals($expected, $withExpiry->expiresAt);
    }

    public function testExpiresInPreservesTokenValue(): void
    {
        // Arrange
        $token = Token::create(TokenType::Access);

        // Act
        $withExpiry = $token->expiresIn(3600);

        // Assert
        $this->assertSame($token->value, $withExpiry->value);
    }

    // --- Token::forSubject() ---

    public function testForSubjectReturnsNewTokenWithSubject(): void
    {
        // Arrange
        $token = Token::create(TokenType::Access);

        // Act
        $withSubject = $token->forSubject('user:42');

        // Assert
        $this->assertSame('user:42', $withSubject->subject);
    }

    public function testForSubjectDoesNotMutateOriginalToken(): void
    {
        // Arrange
        $token = Token::create(TokenType::Access);

        // Act
        $token->forSubject('user:42');

        // Assert
        $this->assertNull($token->subject);
    }

    public function testForSubjectPreservesTokenValue(): void
    {
        // Arrange
        $token = Token::create(TokenType::Access);

        // Act
        $withSubject = $token->forSubject('user:42');

        // Assert
        $this->assertSame($token->value, $withSubject->value);
    }

    // --- Token::withClaims() ---

    public function testWithClaimsMergesClaimsIntoToken(): void
    {
        // Arrange
        $token = Token::create(TokenType::Access);

        // Act
        $withClaims = $token->withClaims(['role' => 'admin', 'tenant' => 'acme']);

        // Assert
        $this->assertSame(['role' => 'admin', 'tenant' => 'acme'], $withClaims->claims);
    }

    public function testWithClaimsMergesAdditionalClaims(): void
    {
        // Arrange
        $token = Token::create(TokenType::Access)->withClaims(['role' => 'user']);

        // Act
        $withMore = $token->withClaims(['tenant' => 'acme']);

        // Assert
        $this->assertSame(['role' => 'user', 'tenant' => 'acme'], $withMore->claims);
    }

    public function testWithClaimsDoesNotMutateOriginalToken(): void
    {
        // Arrange
        $token = Token::create(TokenType::Access);

        // Act
        $token->withClaims(['role' => 'admin']);

        // Assert
        $this->assertSame([], $token->claims);
    }

    public function testWithClaimsOverwritesExistingKeyOnMerge(): void
    {
        // Arrange
        $token = Token::create(TokenType::Access)->withClaims(['role' => 'user']);

        // Act
        $updated = $token->withClaims(['role' => 'admin']);

        // Assert
        $this->assertSame('admin', $updated->claims['role']);
    }

    // --- Token::hash() ---

    public function testHashReturnsHashedToken(): void
    {
        // Arrange
        $token = Token::create(TokenType::Access);

        // Act
        $hashed = $token->hash();

        // Assert
        $this->assertInstanceOf(HashedToken::class, $hashed);
    }

    public function testHashProducesSha256OfTokenValue(): void
    {
        // Arrange
        $token = Token::create(TokenType::Access);

        // Act
        $hashed = $token->hash();

        // Assert
        $this->assertSame(hash('sha256', $token->value), $hashed->hash);
    }

    public function testHashPreservesTokenType(): void
    {
        // Arrange
        $token = Token::create(TokenType::Refresh);

        // Act
        $hashed = $token->hash();

        // Assert
        $this->assertSame(TokenType::Refresh, $hashed->type);
    }

    public function testHashPreservesSubjectAndClaims(): void
    {
        // Arrange
        $token = Token::create(TokenType::Access)
            ->forSubject('user:7')
            ->withClaims(['scope' => 'read']);

        // Act
        $hashed = $token->hash();

        // Assert
        $this->assertSame('user:7', $hashed->subject);
        $this->assertSame(['scope' => 'read'], $hashed->claims);
    }

    // --- Token::isExpired() ---

    public function testIsExpiredReturnsFalseWhenNoExpirySet(): void
    {
        // Arrange
        $token = Token::create(TokenType::Access);

        // Act & Assert
        $this->assertFalse($token->isExpired());
    }

    public function testIsExpiredReturnsFalseWhenExpiryIsInFuture(): void
    {
        // Arrange
        $token = Token::create(TokenType::Access)->expiresIn(3600);

        // Act & Assert
        $this->assertFalse($token->isExpired());
    }

    public function testIsExpiredReturnsTrueWhenExpiryIsInPast(): void
    {
        // Arrange
        $token = Token::create(TokenType::Access)->expiresIn(-1);

        // Act & Assert
        $this->assertTrue($token->isExpired());
    }
}
