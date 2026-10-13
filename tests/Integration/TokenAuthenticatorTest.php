<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Tests\Integration;

use DateTimeImmutable;
use JardisAdapter\DbConnection\Factory\ConnectionFactory;
use JardisSupport\Auth\Data\Credential;
use JardisSupport\Auth\Data\HashedToken;
use JardisSupport\Auth\Data\Subject;
use JardisSupport\Auth\DbTokenStore;
use JardisSupport\Auth\SessionManager;
use JardisSupport\Auth\Tests\Support\TokenTable;
use JardisSupport\Auth\TokenAuthenticator;
use JardisSupport\Contract\Auth\AuthenticatorInterface;
use JardisSupport\Contract\Auth\TenantAwareAuthResultInterface;
use JardisSupport\Contract\Auth\TokenType;
use PHPUnit\Framework\TestCase;

/** TokenAuthenticator resolves a token to subject and tenant, backed by DbTokenStore on real MariaDB. */
final class TokenAuthenticatorTest extends TestCase
{
    private DbTokenStore $store;
    private SessionManager $sessions;
    private TokenAuthenticator $authenticator;

    protected function setUp(): void
    {
        $connection = (new ConnectionFactory())->mysql(
            host: (string) getenv('MARIADB_HOST'),
            user: (string) getenv('MARIADB_USER'),
            password: (string) getenv('MARIADB_PASSWORD'),
            database: (string) getenv('MARIADB_DATABASE'),
            port: (int) getenv('MARIADB_PORT'),
        );
        TokenTable::recreate($connection);

        $this->store = new DbTokenStore($connection);
        $this->sessions = new SessionManager($this->store);
        $this->authenticator = new TokenAuthenticator($this->store);
    }

    public function testValidAccessTokenYieldsSubjectAndTenant(): void
    {
        $created = $this->sessions->create(Subject::from('42'), ['tenant' => 'acme']);

        $result = $this->authenticator->authenticate(Credential::token($created->accessToken));

        self::assertInstanceOf(TenantAwareAuthResultInterface::class, $result);
        self::assertTrue($result->isSuccess());
        self::assertSame('user:42', $result->getSubject());
        self::assertSame('acme', $result->getTenant());
        self::assertNull($result->getReason());
    }

    public function testImplementsTheAuthenticatorContract(): void
    {
        self::assertInstanceOf(AuthenticatorInterface::class, $this->authenticator);
    }

    public function testValidTokenWithoutTenantClaimYieldsNullTenant(): void
    {
        $created = $this->sessions->create(Subject::from('7'));

        $result = $this->authenticator->authenticate(Credential::token($created->accessToken));

        self::assertTrue($result->isSuccess());
        self::assertSame('user:7', $result->getSubject());
        self::assertNull($result->getTenant());
    }

    public function testCustomTenantClaimName(): void
    {
        $created = $this->sessions->create(Subject::from('1'), ['org' => 'globex', 'tenant' => 'ignored']);
        $authenticator = new TokenAuthenticator($this->store, tenantClaim: 'org');

        $result = $authenticator->authenticate(Credential::token($created->accessToken));

        self::assertSame('globex', $result->getTenant());
    }

    public function testExpiredTokenIsRejectedWithReason(): void
    {
        $this->store->store(new HashedToken(
            hash: hash('sha256', 'expired-plain'),
            type: TokenType::Access,
            subject: 'user:1',
            claims: ['tenant' => 'acme'],
            expiresAt: new DateTimeImmutable('-1 minute'),
            createdAt: new DateTimeImmutable('-1 hour'),
        ));

        $result = $this->authenticator->authenticate(Credential::token('expired-plain'));

        self::assertFalse($result->isSuccess());
        self::assertNull($result->getSubject());
        self::assertNull($result->getTenant());
        self::assertSame('Token expired', $result->getReason());
    }

    public function testRevokedTokenIsRejectedWithReason(): void
    {
        $created = $this->sessions->create(Subject::from('42'), ['tenant' => 'acme']);
        $this->store->revoke(hash('sha256', $created->accessToken));

        $result = $this->authenticator->authenticate(Credential::token($created->accessToken));

        self::assertFalse($result->isSuccess());
        self::assertNull($result->getTenant());
        self::assertSame('Token revoked', $result->getReason());
    }

    public function testRevokeAllForSubjectInvalidatesAuthentication(): void
    {
        $created = $this->sessions->create(Subject::from('42'), ['tenant' => 'acme']);
        $this->sessions->invalidateAll('user:42');

        $result = $this->authenticator->authenticate(Credential::token($created->accessToken));

        self::assertFalse($result->isSuccess());
        self::assertSame('Token revoked', $result->getReason());
    }

    public function testUnknownTokenIsRejected(): void
    {
        $result = $this->authenticator->authenticate(Credential::token('never-issued'));

        self::assertFalse($result->isSuccess());
        self::assertNull($result->getSubject());
        self::assertSame('Invalid token', $result->getReason());
    }

    public function testRefreshTokenIsNotAcceptedAsAccessToken(): void
    {
        $created = $this->sessions->create(Subject::from('42'), ['tenant' => 'acme']);

        $result = $this->authenticator->authenticate(Credential::token($created->refreshToken));

        self::assertFalse($result->isSuccess());
        self::assertSame('Invalid token', $result->getReason());
    }

    public function testNonTokenCredentialIsRejected(): void
    {
        $result = $this->authenticator->authenticate(Credential::password('alice', 'secret'));

        self::assertFalse($result->isSuccess());
        self::assertSame('Unsupported credential type', $result->getReason());
    }

    public function testTokenWithoutSubjectIsRejected(): void
    {
        $this->store->store(new HashedToken(
            hash: hash('sha256', 'anonymous-plain'),
            type: TokenType::Access,
            subject: null,
            claims: ['tenant' => 'acme'],
            expiresAt: null,
            createdAt: new DateTimeImmutable(),
        ));

        $result = $this->authenticator->authenticate(Credential::token('anonymous-plain'));

        self::assertFalse($result->isSuccess());
        self::assertSame('Invalid token', $result->getReason());
    }

    public function testNonStringTenantClaimIsTreatedAsAbsent(): void
    {
        $created = $this->sessions->create(Subject::from('5'), ['tenant' => ['not', 'a', 'string']]);

        $result = $this->authenticator->authenticate(Credential::token($created->accessToken));

        self::assertTrue($result->isSuccess());
        self::assertNull($result->getTenant());
    }
}
