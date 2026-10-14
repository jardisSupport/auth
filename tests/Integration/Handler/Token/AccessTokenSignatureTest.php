<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Tests\Integration\Handler\Token;

use InvalidArgumentException;
use JardisSupport\Auth\Exception\TokenExpiredException;
use JardisSupport\Auth\Handler\Token\SignAccessToken;
use JardisSupport\Auth\Handler\Token\VerifyAccessToken;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** SignAccessToken and VerifyAccessToken: sealed payload round trip, tamper and foreign-token rejection. */
final class AccessTokenSignatureTest extends TestCase
{
    private const NOW = 1_800_000_000;

    private string $key;
    private SignAccessToken $sign;
    private VerifyAccessToken $verify;

    protected function setUp(): void
    {
        $this->key = str_repeat('k', 32);
        $this->sign = new SignAccessToken($this->key);
        $this->verify = new VerifyAccessToken($this->key, fn (): int => self::NOW);
    }

    /** @return array<string, mixed> */
    private function payload(string $typ = 'access', int $exp = self::NOW + 900): array
    {
        return [
            'typ' => $typ,
            'sub' => 'user:42',
            'sid' => 'abc',
            'iat' => self::NOW,
            'exp' => $exp,
            'claims' => ['tenant' => 'acme', 'url' => 'a/b'],
        ];
    }

    public function testRoundTripReturnsThePayload(): void
    {
        $token = ($this->sign)($this->payload());

        self::assertSame($this->payload(), ($this->verify)($token));
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/', $token);
    }

    public function testManipulatedPayloadByteIsRejected(): void
    {
        [$segment, $mac] = explode('.', ($this->sign)($this->payload()));
        $segment[5] = $segment[5] === 'A' ? 'B' : 'A';

        self::assertNull(($this->verify)($segment . '.' . $mac));
    }

    public function testManipulatedMacByteIsRejected(): void
    {
        [$segment, $mac] = explode('.', ($this->sign)($this->payload()));
        $mac[3] = $mac[3] === 'A' ? 'B' : 'A';

        self::assertNull(($this->verify)($segment . '.' . $mac));
    }

    public function testWrongKeyIsRejected(): void
    {
        $token = (new SignAccessToken(str_repeat('x', 32)))($this->payload());

        self::assertNull(($this->verify)($token));
    }

    public function testRefreshTypedPayloadIsRejectedAsAccessToken(): void
    {
        self::assertNull(($this->verify)(($this->sign)($this->payload('refresh'))));
    }

    public function testExpiredTokenThrowsOnlyWhenAuthentic(): void
    {
        $expired = ($this->sign)($this->payload(exp: self::NOW));

        $this->expectException(TokenExpiredException::class);
        ($this->verify)($expired);
    }

    public function testExpiredTokenWithForgedMacIsJustInvalid(): void
    {
        $forged = (new SignAccessToken(str_repeat('x', 32)))($this->payload(exp: self::NOW - 10));

        self::assertNull(($this->verify)($forged));
    }

    public function testPayloadWithoutIntegerExpIsRejected(): void
    {
        $payload = $this->payload();
        unset($payload['exp']);

        self::assertNull(($this->verify)(($this->sign)($payload)));
    }

    #[DataProvider('malformedTokens')]
    public function testMalformedTokensAreRejected(string $token): void
    {
        self::assertNull(($this->verify)($token));
    }

    /** @return array<string, array{string}> */
    public static function malformedTokens(): array
    {
        return [
            'empty' => [''],
            'no dot' => ['abcdef'],
            'three parts' => ['a.b.c'],
            'empty mac' => ['abc.'],
            'empty payload' => ['.abc'],
            'not base64url' => ['!!!.???'],
            'padded base64' => ['e30=.e30='],
        ];
    }

    public function testKeyOfWrongLengthIsRejectedByBothHandlers(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new SignAccessToken('short');
    }

    public function testVerifierRejectsKeyOfWrongLength(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new VerifyAccessToken(str_repeat('k', 33));
    }
}
