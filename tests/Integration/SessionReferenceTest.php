<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Tests\Integration;

use JardisAdapter\DbConnection\Factory\ConnectionFactory;
use JardisSupport\Auth\Data\Credential;
use JardisSupport\Auth\Data\Event\SessionInvalidated;
use JardisSupport\Auth\Data\HashedToken;
use JardisSupport\Auth\Data\Subject;
use JardisSupport\Auth\DbTokenStore;
use JardisSupport\Auth\SessionManager;
use JardisSupport\Auth\Tests\Support\TokenTable;
use JardisSupport\Auth\TokenAuthenticator;
use JardisSupport\Contract\Auth\SessionAwareAuthResultInterface;
use PHPUnit\Framework\TestCase;

/** Token session resolves to subject id and session reference; the reference revokes exactly that session. */
final class SessionReferenceTest extends TestCase
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

    public function testResultCarriesSubjectIdAndSessionReference(): void
    {
        $created = $this->sessions->create(Subject::from('42'), ['tenant' => 'acme']);

        $result = $this->authenticator->authenticate(Credential::token($created->accessToken));

        self::assertInstanceOf(SessionAwareAuthResultInterface::class, $result);
        self::assertTrue($result->isSuccess());
        self::assertSame('user:42', $result->getSubject());
        self::assertSame('42', $result->getSubjectId());
        self::assertSame('acme', $result->getTenant());
        self::assertSame($created->session->tokenHash, $result->getSessionReference());
    }

    public function testSubjectIdIsTheBareIdForOtherSubjectTypes(): void
    {
        $created = $this->sessions->create(Subject::from('job:7', 'service'));

        $result = $this->authenticator->authenticate(Credential::token($created->accessToken));

        self::assertSame('service:job:7', $result->getSubject());
        self::assertSame('job:7', $result->getSubjectId());
    }

    public function testFailureCarriesNeitherSubjectIdNorSessionReference(): void
    {
        $result = $this->authenticator->authenticate(Credential::token('never-issued'));

        self::assertFalse($result->isSuccess());
        self::assertNull($result->getSubjectId());
        self::assertNull($result->getSessionReference());
    }

    public function testInvalidateByReferenceRevokesOnlyThatSession(): void
    {
        $first = $this->sessions->create(Subject::from('42'), ['tenant' => 'acme']);
        $second = $this->sessions->create(Subject::from('42'), ['tenant' => 'acme']);
        $reference = (string) $this->authenticator
            ->authenticate(Credential::token($first->accessToken))
            ->getSessionReference();

        $event = $this->sessions->invalidateByReference($reference);

        $revoked = $this->authenticator->authenticate(Credential::token($first->accessToken));
        $stillValid = $this->authenticator->authenticate(Credential::token($second->accessToken));
        self::assertFalse($revoked->isSuccess());
        self::assertSame('Token revoked', $revoked->getReason());
        self::assertTrue($stillValid->isSuccess());
        self::assertSame('user:42', $stillValid->getSubject());
        self::assertInstanceOf(SessionInvalidated::class, $event);
        self::assertSame('user:42', $event->subject);
        self::assertSame($reference, $event->tokenHash);
    }

    public function testInvalidateByUnknownReferenceIsANoOp(): void
    {
        $created = $this->sessions->create(Subject::from('42'));

        $event = $this->sessions->invalidateByReference(HashedToken::hashOf('never-issued'));

        self::assertSame('', $event->subject);
        self::assertTrue($this->authenticator->authenticate(Credential::token($created->accessToken))->isSuccess());
    }

    public function testHashOfEqualsTheStoredHash(): void
    {
        $created = $this->sessions->create(Subject::from('42'));

        $stored = $this->store->find(HashedToken::hashOf($created->accessToken));

        self::assertNotNull($stored);
        self::assertSame($created->session->tokenHash, $stored->getHash());
        self::assertSame(hash('sha256', $created->accessToken), HashedToken::hashOf($created->accessToken));
    }
}
