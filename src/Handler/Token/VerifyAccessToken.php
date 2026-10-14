<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Handler\Token;

use Closure;
use InvalidArgumentException;
use JardisSupport\Auth\Exception\TokenExpiredException;

/**
 * Verifies a signed access token without any store: form, MAC (constant time), `typ === access`, expiry.
 *
 * Returns the payload, or null for every malformed, forged or foreign token. A token whose MAC is valid
 * but whose `exp` has passed throws TokenExpiredException (only authentic tokens reveal their expiry).
 */
final class VerifyAccessToken
{
    private readonly string $key;

    /** @var Closure(): int */
    private readonly Closure $clock;

    /**
     * @param (Closure(): int)|null $clock unix timestamp source, defaults to `time()`
     */
    public function __construct(#[\SensitiveParameter] string $key, ?Closure $clock = null)
    {
        if (strlen($key) !== SODIUM_CRYPTO_AUTH_KEYBYTES) {
            throw new InvalidArgumentException(
                'Access token key must be exactly ' . SODIUM_CRYPTO_AUTH_KEYBYTES . ' bytes'
            );
        }

        $this->key = $key;
        $this->clock = $clock ?? time(...);
    }

    /**
     * @return array<string, mixed>|null
     * @throws TokenExpiredException
     */
    public function __invoke(string $token): ?array
    {
        $parts = explode('.', $token);

        if (count($parts) !== 2) {
            return null;
        }

        [$segment, $macSegment] = $parts;
        $mac = self::decode($macSegment);
        $json = self::decode($segment);

        if ($mac === null || $json === null || strlen($mac) !== SODIUM_CRYPTO_AUTH_BYTES) {
            return null;
        }

        if (!sodium_crypto_auth_verify($mac, $segment, $this->key)) {
            return null;
        }

        $payload = json_decode($json, true);

        if (!is_array($payload) || ($payload['typ'] ?? null) !== 'access' || !is_int($payload['exp'] ?? null)) {
            return null;
        }

        if ($payload['exp'] <= ($this->clock)()) {
            throw new TokenExpiredException('Token has expired');
        }

        return $payload;
    }

    /** Strict base64url decode; null unless the input is the canonical unpadded encoding. */
    private static function decode(string $segment): ?string
    {
        if ($segment === '') {
            return null;
        }

        $bytes = base64_decode(strtr($segment, '-_', '+/'), true);

        if ($bytes === false || SignAccessToken::encode($bytes) !== $segment) {
            return null;
        }

        return $bytes;
    }
}
