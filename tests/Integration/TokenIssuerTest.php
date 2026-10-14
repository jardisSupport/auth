<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Tests\Integration;

use JardisSupport\Auth\Data\HashedToken;
use JardisSupport\Auth\Data\IssuedToken;
use JardisSupport\Auth\Data\Subject;
use JardisSupport\Auth\Tests\Support\InMemoryTokenStore;
use JardisSupport\Auth\TokenIssuer;
use JardisSupport\Contract\Auth\TokenType;
use PHPUnit\Framework\TestCase;

final class TokenIssuerTest extends TestCase
{
    public function testIssuedTokenIsStoredAsHashOnly(): void
    {
        // Arrange
        $store = new InMemoryTokenStore();
        $issuer = new TokenIssuer($store);

        // Act
        $issued = $issuer->issue(TokenType::PasswordReset, Subject::from('42'), 3600);

        // Assert
        self::assertInstanceOf(IssuedToken::class, $issued);
        self::assertSame(HashedToken::hashOf($issued->plain), $issued->hashed->hash);
        self::assertNotNull($store->find($issued->hashed->hash));
        self::assertNull($store->find($issued->plain), 'plain value is never a store key');
    }

    public function testIssuedTokenCarriesTypeSubjectClaimsAndExpiry(): void
    {
        // Arrange
        $store = new InMemoryTokenStore();
        $issuer = new TokenIssuer($store, 16);

        // Act
        $issued = $issuer->issue(TokenType::Verification, Subject::from('abc', 'invitation'), 600, ['tenant' => 'acme']);

        // Assert
        $stored = $store->find($issued->hashed->hash);
        self::assertNotNull($stored);
        self::assertSame(TokenType::Verification, $stored->getType());
        self::assertSame('invitation:abc', $stored->getSubject());
        self::assertSame(['tenant' => 'acme'], $stored->getClaims());
        self::assertNotNull($stored->getExpiresAt());
        self::assertEqualsWithDelta(600, $stored->getExpiresAt()->getTimestamp() - $stored->getCreatedAt()->getTimestamp(), 1);
        self::assertSame(32, strlen($issued->plain), 'token length 16 bytes as hex');
        self::assertFalse($stored->isRevoked());
    }
}
