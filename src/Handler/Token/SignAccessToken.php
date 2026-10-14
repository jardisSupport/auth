<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Handler\Token;

use InvalidArgumentException;

/**
 * Seals an access-token payload: `base64url(json payload) . '.' . base64url(mac)`.
 *
 * The MAC is `sodium_crypto_auth` (HMAC-SHA512-256) over the encoded payload segment. No header, no `alg`.
 */
final class SignAccessToken
{
    private readonly string $key;

    public function __construct(#[\SensitiveParameter] string $key)
    {
        if (strlen($key) !== SODIUM_CRYPTO_AUTH_KEYBYTES) {
            throw new InvalidArgumentException(
                'Access token key must be exactly ' . SODIUM_CRYPTO_AUTH_KEYBYTES . ' bytes'
            );
        }

        $this->key = $key;
    }

    /**
     * @param array<string, mixed> $payload
     * @throws \JsonException when the payload cannot be encoded
     */
    public function __invoke(array $payload): string
    {
        $segment = self::encode(json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));

        return $segment . '.' . self::encode(sodium_crypto_auth($segment, $this->key));
    }

    /** base64url without padding. */
    public static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
