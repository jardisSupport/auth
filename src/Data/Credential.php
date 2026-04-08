<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Data;

use JardisSupport\Contract\Auth\CredentialInterface;
use JardisSupport\Contract\Auth\CredentialType;

/** Immutable value object representing authentication credentials with type, value, and identifier. */
final readonly class Credential implements CredentialInterface
{
    private function __construct(
        public CredentialType $type,
        public string $value,
        public string $identifier,
    ) {
    }

    public static function password(string $identifier, string $password): self
    {
        return new self(CredentialType::Password, $password, $identifier);
    }

    public static function apiKey(string $identifier, string $key): self
    {
        return new self(CredentialType::ApiKey, $key, $identifier);
    }

    public static function token(string $token): self
    {
        return new self(CredentialType::Token, $token, $token);
    }

    public function getType(): CredentialType
    {
        return $this->type;
    }

    public function getValue(): string
    {
        return $this->value;
    }

    public function getIdentifier(): string
    {
        return $this->identifier;
    }
}
