<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Tests\Integration;

use JardisSupport\Auth\PasswordHasher;
use PHPUnit\Framework\TestCase;

final class PasswordHasherTest extends TestCase
{
    public function testHashAndVerifyWithCorrectPasswordReturnsTrue(): void
    {
        // Arrange
        $hasher = new PasswordHasher();
        $password = 'secret-password-123';

        // Act
        $hash = $hasher->hash($password);
        $result = $hasher->verify($password, $hash);

        // Assert
        self::assertTrue($result);
        self::assertNotSame($password, $hash);
    }

    public function testVerifyWithWrongPasswordReturnsFalse(): void
    {
        // Arrange
        $hasher = new PasswordHasher();
        $hash = $hasher->hash('correct-password');

        // Act
        $result = $hasher->verify('wrong-password', $hash);

        // Assert
        self::assertFalse($result);
    }

    public function testNeedsRehashReturnsFalseForHashWithSameOptions(): void
    {
        // Arrange
        $hasher = PasswordHasher::argon2id();
        $hash = $hasher->hash('my-password');

        // Act
        $result = $hasher->needsRehash($hash);

        // Assert
        self::assertFalse($result);
    }

    public function testNeedsRehashReturnsTrueForHashWithDifferentOptions(): void
    {
        // Arrange
        $originalHasher = PasswordHasher::argon2id(memoryCost: 65536, timeCost: 4);
        $hash = $originalHasher->hash('my-password');

        // Hasher mit anderen Optionen
        $newHasher = PasswordHasher::argon2id(memoryCost: 131072, timeCost: 6);

        // Act
        $result = $newHasher->needsRehash($hash);

        // Assert
        self::assertTrue($result);
    }

    public function testArgon2idFactoryCreatesHasherWithArgon2idAlgorithm(): void
    {
        // Arrange
        $hasher = PasswordHasher::argon2id();
        $password = 'argon2id-password';

        // Act
        $hash = $hasher->hash($password);

        // Assert
        self::assertStringStartsWith('$argon2id$', $hash);
        self::assertTrue($hasher->verify($password, $hash));
    }

    public function testArgon2idFactoryWithCustomOptionsCreatesVerifiableHash(): void
    {
        // Arrange
        $hasher = PasswordHasher::argon2id(memoryCost: 65536, timeCost: 3, threads: 1);
        $password = 'custom-options-password';

        // Act
        $hash = $hasher->hash($password);

        // Assert
        self::assertTrue($hasher->verify($password, $hash));
        self::assertFalse($hasher->needsRehash($hash));
    }

    public function testBcryptFactoryCreatesHasherWithBcryptAlgorithm(): void
    {
        // Arrange
        $hasher = PasswordHasher::bcrypt();
        $password = 'bcrypt-password';

        // Act
        $hash = $hasher->hash($password);

        // Assert
        self::assertStringStartsWith('$2y$', $hash);
        self::assertTrue($hasher->verify($password, $hash));
    }

    public function testBcryptFactoryWithCustomCostCreatesVerifiableHash(): void
    {
        // Arrange
        $hasher = PasswordHasher::bcrypt(cost: 10);
        $password = 'bcrypt-cost-password';

        // Act
        $hash = $hasher->hash($password);

        // Assert
        self::assertTrue($hasher->verify($password, $hash));
        self::assertFalse($hasher->needsRehash($hash));
    }

    public function testHashProducesDifferentHashesForSamePassword(): void
    {
        // Arrange
        $hasher = new PasswordHasher();
        $password = 'same-password';

        // Act
        $hash1 = $hasher->hash($password);
        $hash2 = $hasher->hash($password);

        // Assert (salt macht jeden Hash einzigartig)
        self::assertNotSame($hash1, $hash2);
        self::assertTrue($hasher->verify($password, $hash1));
        self::assertTrue($hasher->verify($password, $hash2));
    }
}
