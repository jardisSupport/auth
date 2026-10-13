<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Tests\Integration;

use DateTimeImmutable;
use InvalidArgumentException;
use JardisSupport\Auth\Data\HashedToken;
use JardisSupport\Auth\Data\Token;
use JardisSupport\Auth\DbTokenStore;
use JardisSupport\Auth\Tests\Support\TokenTable;
use JardisSupport\Contract\Auth\TokenType;
use JardisSupport\Contract\DbConnection\DbConnectionInterface;
use PHPUnit\Framework\TestCase;

/** TokenStoreInterface behaviour of DbTokenStore against a real database (one subclass per driver). */
abstract class DbTokenStoreTestCase extends TestCase
{
    protected DbConnectionInterface $connection;
    protected DbTokenStore $store;

    abstract protected function createConnection(): DbConnectionInterface;

    protected function setUp(): void
    {
        $this->connection = $this->createConnection();
        TokenTable::recreate($this->connection);
        $this->store = new DbTokenStore($this->connection);
    }

    public function testStoreAndFindRoundTripsAllFields(): void
    {
        $token = Token::create(TokenType::Access)
            ->forSubject('user:42')
            ->expiresIn(3600)
            ->withClaims(['tenant' => 'acme', 'roles' => ['admin', 'editor']]);
        $hashed = $token->hash();

        $this->store->store($hashed);
        $found = $this->store->find($hashed->hash);

        self::assertNotNull($found);
        self::assertSame($hashed->hash, $found->getHash());
        self::assertSame(TokenType::Access, $found->getType());
        self::assertSame('user:42', $found->getSubject());
        self::assertSame(['tenant' => 'acme', 'roles' => ['admin', 'editor']], $found->getClaims());
        self::assertEquals(
            $hashed->expiresAt?->getTimestamp(),
            $found->getExpiresAt()?->getTimestamp(),
        );
        self::assertEquals($hashed->createdAt->getTimestamp(), $found->getCreatedAt()->getTimestamp());
        self::assertFalse($found->isExpired());
        self::assertFalse($found->isRevoked());
    }

    public function testOnlyTheHashIsStoredNeverThePlainToken(): void
    {
        $token = Token::create(TokenType::Access)->forSubject('user:1');
        $this->store->store($token->hash());

        $dump = json_encode(
            $this->connection->pdo()->query('SELECT * FROM auth_tokens')->fetchAll(),
            JSON_THROW_ON_ERROR,
        );

        self::assertStringNotContainsString($token->value, $dump);
        self::assertStringContainsString($token->hash()->hash, $dump);
    }

    public function testFindUnknownHashReturnsNull(): void
    {
        self::assertNull($this->store->find(hash('sha256', 'does-not-exist')));
    }

    public function testStoreWithoutSubjectAndExpiry(): void
    {
        $hashed = Token::create(TokenType::ApiKey)->hash();

        $this->store->store($hashed);
        $found = $this->store->find($hashed->hash);

        self::assertNotNull($found);
        self::assertNull($found->getSubject());
        self::assertNull($found->getExpiresAt());
        self::assertSame([], $found->getClaims());
        self::assertFalse($found->isExpired());
    }

    public function testRevokeMarksOnlyThatToken(): void
    {
        $a = Token::create(TokenType::Access)->forSubject('user:1')->hash();
        $b = Token::create(TokenType::Access)->forSubject('user:1')->hash();
        $this->store->store($a);
        $this->store->store($b);

        $this->store->revoke($a->hash);

        self::assertTrue($this->store->find($a->hash)?->isRevoked());
        self::assertFalse($this->store->find($b->hash)?->isRevoked());
    }

    public function testRevokeUnknownHashIsNoOp(): void
    {
        $this->store->revoke(hash('sha256', 'unknown'));

        self::assertNull($this->store->find(hash('sha256', 'unknown')));
    }

    public function testRevokeAllForSubjectLeavesOtherSubjectsUntouched(): void
    {
        $a1 = Token::create(TokenType::Access)->forSubject('user:1')->hash();
        $a2 = Token::create(TokenType::Refresh)->forSubject('user:1')->hash();
        $b = Token::create(TokenType::Access)->forSubject('user:2')->hash();
        foreach ([$a1, $a2, $b] as $hashed) {
            $this->store->store($hashed);
        }

        $this->store->revokeAllForSubject('user:1');

        self::assertTrue($this->store->find($a1->hash)?->isRevoked());
        self::assertTrue($this->store->find($a2->hash)?->isRevoked());
        self::assertFalse($this->store->find($b->hash)?->isRevoked());
    }

    public function testExpiredTokenIsReportedAsExpired(): void
    {
        $expired = new HashedToken(
            hash: hash('sha256', 'old'),
            type: TokenType::Access,
            subject: 'user:1',
            claims: [],
            expiresAt: new DateTimeImmutable('-1 hour'),
            createdAt: new DateTimeImmutable('-2 hours'),
        );
        $this->store->store($expired);

        self::assertTrue($this->store->find($expired->hash)?->isExpired());
    }

    public function testDeleteExpiredRemovesOnlyExpiredAndReturnsCount(): void
    {
        $expired = new HashedToken(
            hash: hash('sha256', 'old'),
            type: TokenType::Access,
            subject: 'user:1',
            claims: [],
            expiresAt: new DateTimeImmutable('-1 hour'),
            createdAt: new DateTimeImmutable('-2 hours'),
        );
        $valid = Token::create(TokenType::Access)->forSubject('user:1')->expiresIn(3600)->hash();
        $neverExpires = Token::create(TokenType::ApiKey)->forSubject('user:1')->hash();
        foreach ([$expired, $valid, $neverExpires] as $hashed) {
            $this->store->store($hashed);
        }

        self::assertSame(1, $this->store->deleteExpired());

        self::assertNull($this->store->find($expired->hash));
        self::assertNotNull($this->store->find($valid->hash));
        self::assertNotNull($this->store->find($neverExpires->hash));
        self::assertSame(0, $this->store->deleteExpired());
    }

    public function testInvalidTableNameIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new DbTokenStore($this->connection, 'auth_tokens; DROP TABLE users');
    }

    public function testCustomTableName(): void
    {
        $this->connection->pdo()->exec('DROP TABLE IF EXISTS custom_tokens');
        $this->connection->pdo()->exec(
            str_replace(
                'auth_tokens',
                'custom_tokens',
                (string) file_get_contents(
                    dirname(__DIR__, 2) . '/resources/sql/' . $this->connection->getDriverName() . '.sql',
                ),
            ),
        );
        $store = new DbTokenStore($this->connection, 'custom_tokens');
        $hashed = Token::create(TokenType::Access)->forSubject('user:9')->hash();

        $store->store($hashed);

        self::assertNotNull($store->find($hashed->hash));
        self::assertNull($this->store->find($hashed->hash));
        $this->connection->pdo()->exec('DROP TABLE custom_tokens');
    }
}
