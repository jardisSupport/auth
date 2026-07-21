<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Tests\Integration\Data;

use JardisSupport\Auth\Data\Credential;
use JardisSupport\Contract\Auth\CredentialType;
use PHPUnit\Framework\TestCase;

final class CredentialTest extends TestCase
{
    // --- Credential::password() ---

    public function testPasswordSetsTypeToPassword(): void
    {
        // Arrange & Act
        $credential = Credential::password('alice@example.com', 'secret123');

        // Assert
        $this->assertSame(CredentialType::Password, $credential->type);
    }

    public function testPasswordSetsIdentifierToGivenIdentifier(): void
    {
        // Arrange & Act
        $credential = Credential::password('alice@example.com', 'secret123');

        // Assert
        $this->assertSame('alice@example.com', $credential->identifier);
    }

    public function testPasswordSetsValueToGivenPassword(): void
    {
        // Arrange & Act
        $credential = Credential::password('alice@example.com', 'secret123');

        // Assert
        $this->assertSame('secret123', $credential->value);
    }

    // --- Credential::apiKey() ---

    public function testApiKeySetsTypeToApiKey(): void
    {
        // Arrange & Act
        $credential = Credential::apiKey('my-service', 'my-api-key-abc');

        // Assert
        $this->assertSame(CredentialType::ApiKey, $credential->type);
    }

    public function testApiKeySetsValueToGivenKey(): void
    {
        // Arrange & Act
        $credential = Credential::apiKey('my-service', 'my-api-key-abc');

        // Assert
        $this->assertSame('my-api-key-abc', $credential->value);
    }

    public function testApiKeySetsIdentifierSeparateFromKey(): void
    {
        // Arrange & Act
        $credential = Credential::apiKey('my-service', 'my-api-key-abc');

        // Assert
        $this->assertSame('my-service', $credential->identifier);
    }

    // --- Credential::token() ---

    public function testTokenSetsTypeToToken(): void
    {
        // Arrange & Act
        $credential = Credential::token('bearer-token-value');

        // Assert
        $this->assertSame(CredentialType::Token, $credential->type);
    }

    public function testTokenSetsValueToGivenToken(): void
    {
        // Arrange & Act
        $credential = Credential::token('bearer-token-value');

        // Assert
        $this->assertSame('bearer-token-value', $credential->value);
    }

    public function testTokenSetsIdentifierToGivenToken(): void
    {
        // Arrange & Act
        $credential = Credential::token('bearer-token-value');

        // Assert
        $this->assertSame('bearer-token-value', $credential->identifier);
    }
}
