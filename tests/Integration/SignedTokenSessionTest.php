<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Tests\Integration;

use JardisSupport\Auth\Data\Credential;
use JardisSupport\Auth\Data\HashedToken;
use JardisSupport\Auth\Data\Subject;
use JardisSupport\Auth\Exception\AuthenticationException;
use JardisSupport\Auth\Handler\Token\SignAccessToken;
use JardisSupport\Auth\SessionManager;
use JardisSupport\Auth\SignedTokenAuthenticator;
use JardisSupport\Auth\Tests\Support\CountingTokenStore;
use JardisSupport\Auth\Tests\Support\InMemoryTokenStore;
use JardisSupport\Contract\Auth\AuthenticatorInterface;
use PHPUnit\Framework\TestCase;

/** Signed access token + opaque refresh token: verification without store, revocation at refresh. */
final class SignedTokenSessionTest extends TestCase
{
    private string $key;
    private CountingTokenStore $store;
    private SessionManager $sessions;
    private SignedTokenAuthenticator $authenticator;

    protected function setUp(): void
    {
        $this->key = str_repeat('k', 32);
        $this->store = new CountingTokenStore();
        $this->sessions = new SessionManager($this->store, $this->key);
        $this->authenticator = new SignedTokenAuthenticator($this->key);
    }

    public function testCreatedAccessTokenVerifiesWithoutAnyStoreAccess(): void
    {
        $created = $this->sessions->create(Subject::from('42'), ['tenant' => 'acme']);
        $this->store->finds = 0;

        $result = $this->authenticator->authenticate(Credential::token($created->accessToken));

        self::assertTrue($result->isSuccess());
        self::assertSame('user:42', $result->getSubject());
        self::assertSame('42', $result->getSubjectId());
        self::assertSame('acme', $result->getTenant());
        self::assertSame(HashedToken::hashOf($created->refreshToken), $result->getSessionReference());
        self::assertSame(0, $this->store->finds);
        self::assertNotNull($this->store->find(HashedToken::hashOf($created->refreshToken)));
    }

    public function testImplementsTheAuthenticatorContract(): void
    {
        self::assertInstanceOf(AuthenticatorInterface::class, $this->authenticator);
    }

    public function testTenantClaimNameIsConfigurable(): void
    {
        $created = $this->sessions->create(Subject::from('1'), ['org' => 'globex', 'tenant' => 'ignored']);

        $result = (new SignedTokenAuthenticator($this->key, tenantClaim: 'org'))
            ->authenticate(Credential::token($created->accessToken));

        self::assertSame('globex', $result->getTenant());
    }

    public function testMissingOrNonStringTenantYieldsNull(): void
    {
        $plain = $this->sessions->create(Subject::from('7'));
        $odd = $this->sessions->create(Subject::from('7'), ['tenant' => ['x']]);

        self::assertNull($this->authenticator->authenticate(Credential::token($plain->accessToken))->getTenant());
        self::assertNull($this->authenticator->authenticate(Credential::token($odd->accessToken))->getTenant());
    }

    public function testExpiredAccessTokenIsRejectedWithReason(): void
    {
        $created = $this->sessions->create(Subject::from('42'));
        $later = new SignedTokenAuthenticator($this->key, clock: fn (): int => time() + 901);

        $result = $later->authenticate(Credential::token($created->accessToken));

        self::assertFalse($result->isSuccess());
        self::assertSame('Token expired', $result->getReason());
        self::assertNull($result->getSubject());
    }

    public function testDefaultAccessTtlIs900Seconds(): void
    {
        $created = $this->sessions->create(Subject::from('42'));

        $edge = new SignedTokenAuthenticator($this->key, clock: fn (): int => time() + 890);

        self::assertTrue($edge->authenticate(Credential::token($created->accessToken))->isSuccess());
        self::assertEqualsWithDelta(900, $created->session->expiresAt->getTimestamp() - time(), 2);
    }

    public function testForeignAndForgedTokensAreInvalid(): void
    {
        $created = $this->sessions->create(Subject::from('42'));
        $foreign = (new SessionManager(new InMemoryTokenStore(), str_repeat('x', 32)))->create(Subject::from('42'));

        foreach (['never-issued', $created->refreshToken, $foreign->accessToken] as $token) {
            $result = $this->authenticator->authenticate(Credential::token($token));
            self::assertFalse($result->isSuccess());
            self::assertSame('Invalid token', $result->getReason());
        }
    }

    public function testRefreshTypedSignedTokenIsInvalid(): void
    {
        $token = (new SignAccessToken($this->key))([
            'typ' => 'refresh', 'sub' => 'user:1', 'sid' => 's', 'iat' => time(), 'exp' => time() + 60,
            'claims' => [],
        ]);

        self::assertSame('Invalid token', $this->authenticator->authenticate(Credential::token($token))->getReason());
    }

    public function testPayloadWithoutSubjectOrSessionIsInvalid(): void
    {
        $sign = new SignAccessToken($this->key);
        $base = ['typ' => 'access', 'iat' => time(), 'exp' => time() + 60, 'claims' => []];

        foreach ([$base, $base + ['sub' => 'user:1'], $base + ['sid' => 's'], $base + ['sub' => '', 'sid' => 's']] as $p) {
            $result = $this->authenticator->authenticate(Credential::token($sign($p)));
            self::assertFalse($result->isSuccess());
            self::assertSame('Invalid token', $result->getReason());
        }
    }

    public function testNonTokenCredentialIsRejected(): void
    {
        $result = $this->authenticator->authenticate(Credential::password('alice', 'secret'));

        self::assertSame('Unsupported credential type', $result->getReason());
    }

    public function testRefreshIssuesNewAccessTokenWithNewSession(): void
    {
        $created = $this->sessions->create(Subject::from('42'), ['tenant' => 'acme']);

        $refreshed = $this->sessions->refresh($created->refreshToken);

        $old = $this->authenticator->authenticate(Credential::token($created->accessToken));
        $new = $this->authenticator->authenticate(Credential::token($refreshed->accessToken));
        self::assertTrue($new->isSuccess());
        self::assertSame('acme', $new->getTenant());
        self::assertNotSame($old->getSessionReference(), $new->getSessionReference());
        self::assertSame(HashedToken::hashOf($refreshed->refreshToken), $new->getSessionReference());
    }

    public function testRevokedSessionCannotRefreshButIssuedAccessStaysValidUntilExp(): void
    {
        $created = $this->sessions->create(Subject::from('42'), ['tenant' => 'acme']);
        $reference = (string) $this->authenticator
            ->authenticate(Credential::token($created->accessToken))
            ->getSessionReference();

        $this->sessions->invalidateByReference($reference);

        // Soll (documented): revocation acts on the refresh token, the issued access token lives until `exp`.
        self::assertTrue($this->authenticator->authenticate(Credential::token($created->accessToken))->isSuccess());
        $this->expectException(AuthenticationException::class);
        $this->sessions->refresh($created->refreshToken);
    }

    public function testRotatedKeyInvalidatesEveryIssuedAccessToken(): void
    {
        $created = $this->sessions->create(Subject::from('42'));
        $rotated = new SignedTokenAuthenticator(str_repeat('n', 32));

        self::assertSame('Invalid token', $rotated->authenticate(Credential::token($created->accessToken))->getReason());
    }

    public function testSessionManagerRejectsKeyOfWrongLength(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new SessionManager($this->store, 'too-short');
    }
}
