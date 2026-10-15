<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Tests\Integration;

use JardisSupport\Auth\Data\Credential;
use JardisSupport\Auth\Data\Event\SessionInvalidated;
use JardisSupport\Auth\Handler\Session\InvalidateSessionByReference;
use JardisSupport\Auth\Data\HashedToken;
use JardisSupport\Auth\Data\Subject;
use JardisSupport\Auth\Exception\AuthenticationException;
use JardisSupport\Auth\SessionManager;
use JardisSupport\Auth\SignedTokenAuthenticator;
use JardisSupport\Auth\Tests\Support\InMemoryTokenStore;
use JardisSupport\Contract\Auth\SessionAwareAuthResultInterface;
use PHPUnit\Framework\TestCase;

/** A signed-token session resolves to subject id and session reference; the reference revokes exactly that session. */
final class SessionReferenceTest extends TestCase
{
    private InMemoryTokenStore $store;
    private SessionManager $sessions;
    private SignedTokenAuthenticator $authenticator;

    protected function setUp(): void
    {
        $key = str_repeat('k', 32);
        $this->store = new InMemoryTokenStore();
        $this->sessions = new SessionManager($this->store, $key);
        $this->authenticator = new SignedTokenAuthenticator($key);
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
        self::assertSame(HashedToken::hashOf($created->refreshToken), $result->getSessionReference());
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

    public function testInvalidateByReferenceRevokesOnlyThatSessionsRefresh(): void
    {
        $first = $this->sessions->create(Subject::from('42'), ['tenant' => 'acme']);
        $second = $this->sessions->create(Subject::from('42'), ['tenant' => 'acme']);
        $reference = (string) $this->authenticator
            ->authenticate(Credential::token($first->accessToken))
            ->getSessionReference();

        $this->sessions->invalidateByReference($reference);

        $this->expectException(AuthenticationException::class);
        try {
            $this->sessions->refresh($first->refreshToken);
        } finally {
            self::assertSame('user:42', $this->sessions->refresh($second->refreshToken)->session->subject);
        }
    }

    public function testInvalidateByReferenceHandlerReturnsTheEvent(): void
    {
        $created = $this->sessions->create(Subject::from('42'));
        $reference = $created->session->tokenHash;

        $event = (new InvalidateSessionByReference($this->store))($reference);

        self::assertInstanceOf(SessionInvalidated::class, $event);
        self::assertSame('user:42', $event->subject);
        self::assertSame($reference, $event->tokenHash);
    }

    public function testInvalidateByUnknownReferenceIsANoOp(): void
    {
        $created = $this->sessions->create(Subject::from('42'));

        $this->sessions->invalidateByReference(HashedToken::hashOf('never-issued'));

        self::assertSame('user:42', $this->sessions->refresh($created->refreshToken)->session->subject);
    }
}
