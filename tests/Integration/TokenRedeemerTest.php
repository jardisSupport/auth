<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Tests\Integration;

use JardisSupport\Auth\Data\Subject;
use JardisSupport\Auth\Exception\InvalidCredentialException;
use JardisSupport\Auth\Exception\TokenExpiredException;
use JardisSupport\Auth\Exception\TokenRevokedException;
use JardisSupport\Auth\Tests\Support\InMemoryTokenStore;
use JardisSupport\Auth\TokenIssuer;
use JardisSupport\Auth\TokenRedeemer;
use JardisSupport\Contract\Auth\TokenType;
use PHPUnit\Framework\TestCase;

final class TokenRedeemerTest extends TestCase
{
    private InMemoryTokenStore $store;
    private TokenIssuer $issuer;
    private TokenRedeemer $redeemer;

    protected function setUp(): void
    {
        $this->store = new InMemoryTokenStore();
        $this->issuer = new TokenIssuer($this->store);
        $this->redeemer = new TokenRedeemer($this->store);
    }

    public function testValidTokenIsReturnedAndRevoked(): void
    {
        $issued = $this->issuer->issue(TokenType::PasswordReset, Subject::from('42'), 3600, ['k' => 'v']);

        $redeemed = $this->redeemer->redeem($issued->plain, TokenType::PasswordReset);

        self::assertSame('user:42', $redeemed->getSubject());
        self::assertSame(['k' => 'v'], $redeemed->getClaims());
        self::assertTrue($this->store->find($issued->hashed->hash)?->isRevoked());
    }

    public function testWrongTypeIsRejectedAndNotConsumed(): void
    {
        $issued = $this->issuer->issue(TokenType::PasswordReset, Subject::from('42'), 3600);

        try {
            $this->redeemer->redeem($issued->plain, TokenType::Verification);
            self::fail('expected InvalidCredentialException');
        } catch (InvalidCredentialException) {
            self::assertFalse($this->store->find($issued->hashed->hash)?->isRevoked());
        }
    }

    public function testUnknownTokenIsRejected(): void
    {
        $this->expectException(InvalidCredentialException::class);

        $this->redeemer->redeem('never-issued', TokenType::PasswordReset);
    }

    public function testExpiredTokenThrows(): void
    {
        $issued = $this->issuer->issue(TokenType::PasswordReset, Subject::from('42'), 1);
        $this->store->store(new \JardisSupport\Auth\Data\HashedToken(
            hash: $issued->hashed->hash,
            type: $issued->hashed->type,
            subject: $issued->hashed->subject,
            claims: [],
            expiresAt: new \DateTimeImmutable('-1 hour'),
            createdAt: new \DateTimeImmutable('-2 hours'),
        ));

        $this->expectException(TokenExpiredException::class);

        $this->redeemer->redeem($issued->plain, TokenType::PasswordReset);
    }

    public function testSecondRedemptionThrowsRevoked(): void
    {
        $issued = $this->issuer->issue(TokenType::PasswordReset, Subject::from('42'), 3600);
        $this->redeemer->redeem($issued->plain, TokenType::PasswordReset);

        $this->expectException(TokenRevokedException::class);

        $this->redeemer->redeem($issued->plain, TokenType::PasswordReset);
    }
}
