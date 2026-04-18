<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Tests\Integration\Handler\Token;

use JardisSupport\Auth\Exception\TokenExpiredException;
use JardisSupport\Auth\Exception\TokenRevokedException;
use JardisSupport\Auth\Handler\Token\VerifyToken;
use JardisSupport\Auth\Data\HashedToken;
use JardisSupport\Auth\Data\Token;
use JardisSupport\Contract\Auth\TokenType;
use PHPUnit\Framework\TestCase;

final class VerifyTokenTest extends TestCase
{
    private VerifyToken $verifyToken;

    protected function setUp(): void
    {
        $this->verifyToken = new VerifyToken();
    }

    // --- valid token ---

    public function testInvokeReturnsTrueForValidToken(): void
    {
        // Arrange
        $token  = Token::create(TokenType::Access)->expiresIn(3600);
        $stored = HashedToken::fromToken($token);

        // Act
        $result = ($this->verifyToken)($token->value, $stored);

        // Assert
        $this->assertTrue($result);
    }

    public function testInvokeReturnsTrueForValidTokenWithMatchingExpectedType(): void
    {
        // Arrange
        $token  = Token::create(TokenType::Access)->expiresIn(3600);
        $stored = HashedToken::fromToken($token);

        // Act
        $result = ($this->verifyToken)($token->value, $stored, TokenType::Access);

        // Assert
        $this->assertTrue($result);
    }

    public function testInvokeReturnsTrueForTokenWithNoExpiry(): void
    {
        // Arrange
        $token  = Token::create(TokenType::ApiKey);
        $stored = HashedToken::fromToken($token);

        // Act
        $result = ($this->verifyToken)($token->value, $stored);

        // Assert
        $this->assertTrue($result);
    }

    // --- expired token ---

    public function testInvokeThrowsTokenExpiredExceptionForExpiredToken(): void
    {
        // Arrange
        $token  = Token::create(TokenType::Access)->expiresIn(-1);
        $stored = HashedToken::fromToken($token);

        // Act & Assert
        $this->expectException(TokenExpiredException::class);
        ($this->verifyToken)($token->value, $stored);
    }

    public function testInvokeThrowsTokenExpiredExceptionWithMessage(): void
    {
        // Arrange
        $token  = Token::create(TokenType::Access)->expiresIn(-1);
        $stored = HashedToken::fromToken($token);

        // Act & Assert
        $this->expectException(TokenExpiredException::class);
        $this->expectExceptionMessage('Token has expired');
        ($this->verifyToken)($token->value, $stored);
    }

    // --- revoked token ---

    public function testInvokeThrowsTokenRevokedExceptionForRevokedToken(): void
    {
        // Arrange
        $token   = Token::create(TokenType::Access)->expiresIn(3600);
        $stored  = HashedToken::fromToken($token)->withRevoked();

        // Act & Assert
        $this->expectException(TokenRevokedException::class);
        ($this->verifyToken)($token->value, $stored);
    }

    public function testInvokeThrowsTokenRevokedExceptionWithMessage(): void
    {
        // Arrange
        $token  = Token::create(TokenType::Access)->expiresIn(3600);
        $stored = HashedToken::fromToken($token)->withRevoked();

        // Act & Assert
        $this->expectException(TokenRevokedException::class);
        $this->expectExceptionMessage('Token has been revoked');
        ($this->verifyToken)($token->value, $stored);
    }

    public function testInvokeChecksRevokedBeforeExpiry(): void
    {
        // Arrange — Token ist sowohl revoked als auch expired; revoked wird zuerst geprüft
        $token  = Token::create(TokenType::Access)->expiresIn(-1);
        $stored = HashedToken::fromToken($token)->withRevoked();

        // Act & Assert
        $this->expectException(TokenRevokedException::class);
        ($this->verifyToken)($token->value, $stored);
    }

    // --- wrong hash ---

    public function testInvokeReturnsFalseForWrongPlainToken(): void
    {
        // Arrange
        $token  = Token::create(TokenType::Access)->expiresIn(3600);
        $stored = HashedToken::fromToken($token);

        // Act
        $result = ($this->verifyToken)('wrong-plain-token-value', $stored);

        // Assert
        $this->assertFalse($result);
    }

    public function testInvokeReturnsFalseForTamperedTokenValue(): void
    {
        // Arrange
        $token      = Token::create(TokenType::Access)->expiresIn(3600);
        $stored     = HashedToken::fromToken($token);
        $tampered   = $token->value . 'x';

        // Act
        $result = ($this->verifyToken)($tampered, $stored);

        // Assert
        $this->assertFalse($result);
    }

    // --- wrong type ---

    public function testInvokeReturnsFalseForWrongExpectedType(): void
    {
        // Arrange
        $token  = Token::create(TokenType::Access)->expiresIn(3600);
        $stored = HashedToken::fromToken($token);

        // Act
        $result = ($this->verifyToken)($token->value, $stored, TokenType::Refresh);

        // Assert
        $this->assertFalse($result);
    }

    public function testInvokeReturnsTrueWhenNoExpectedTypeGiven(): void
    {
        // Arrange
        $token  = Token::create(TokenType::Verification)->expiresIn(3600);
        $stored = HashedToken::fromToken($token);

        // Act
        $result = ($this->verifyToken)($token->value, $stored, null);

        // Assert
        $this->assertTrue($result);
    }
}
