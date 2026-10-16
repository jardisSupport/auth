<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Tests\Integration;

use JardisAdapter\DbConnection\Factory\ConnectionFactory;
use JardisSupport\Auth\AuthServices;
use JardisSupport\Auth\Data\Credential;
use JardisSupport\Auth\Data\HashedToken;
use JardisSupport\Auth\Data\IssuedToken;
use JardisSupport\Auth\Data\SessionResult;
use JardisSupport\Auth\Data\Subject;
use JardisSupport\Auth\DbTokenStore;
use JardisSupport\Auth\Exception\InvalidCredentialException;
use JardisSupport\Auth\Exception\TokenExpiredException;
use JardisSupport\Auth\Exception\TokenRevokedException;
use JardisSupport\Auth\PasswordAuthenticator;
use JardisSupport\Auth\PasswordHasher;
use JardisSupport\Auth\SessionManager;
use JardisSupport\Auth\SignedTokenAuthenticator;
use JardisSupport\Auth\Tests\Support\CountingTokenStore;
use JardisSupport\Auth\Tests\Support\FakeUserLookup;
use JardisSupport\Auth\Tests\Support\InMemoryTokenStore;
use JardisSupport\Auth\Tests\Support\TokenTable;
use JardisSupport\Auth\TokenAuthenticator;
use JardisSupport\Auth\TokenIssuer;
use JardisSupport\Auth\TokenRedeemer;
use JardisSupport\Contract\Auth\AuthServicesInterface;
use JardisSupport\Contract\Auth\IssuedTokenInterface;
use JardisSupport\Contract\Auth\RoleAwareAuthResultInterface;
use JardisSupport\Contract\Auth\SessionClaim;
use JardisSupport\Contract\Auth\SessionInterface;
use JardisSupport\Contract\Auth\SessionManagerInterface;
use JardisSupport\Contract\Auth\SessionResultInterface;
use JardisSupport\Contract\Auth\TokenIssuerInterface;
use JardisSupport\Contract\Auth\TokenRedeemerInterface;
use JardisSupport\Contract\Auth\TokenType;
use PHPUnit\Framework\TestCase;

/** The contracts 2.11 auth interfaces: conformance, string subjects, peek, role claim and the AuthServices bundle. */
final class AuthContractsTest extends TestCase
{
    private const KEY = 'abcdefghijklmnopqrstuvwxyz012345';

    private DbTokenStore $store;
    private AuthServices $services;

    protected function setUp(): void
    {
        $connection = (new ConnectionFactory())->sqlite();
        TokenTable::recreate($connection);

        $this->store = new DbTokenStore($connection);
        $this->services = AuthServices::fromStore($this->store, self::KEY, PasswordHasher::bcrypt(4));
    }

    public function testImplementationsConformToTheContractInterfaces(): void
    {
        self::assertInstanceOf(AuthServicesInterface::class, $this->services);
        self::assertInstanceOf(SessionManagerInterface::class, $this->services->sessions());
        self::assertInstanceOf(TokenIssuerInterface::class, $this->services->tokenIssuer());
        self::assertInstanceOf(TokenRedeemerInterface::class, $this->services->tokenRedeemer());
        self::assertInstanceOf(SessionResultInterface::class, $this->services->sessions()->create('user:1'));
        self::assertInstanceOf(
            IssuedTokenInterface::class,
            $this->services->tokenIssuer()->issue(TokenType::Invitation, 'user:1', 60),
        );
    }

    public function testFromStoreYieldsWorkingServices(): void
    {
        $created = $this->services->sessions()->create('user:42', [SessionClaim::TENANT => 'acme']);

        $result = (new SignedTokenAuthenticator(self::KEY))->authenticate(Credential::token($created->getAccessToken()));
        self::assertTrue($result->isSuccess());
        self::assertSame('user:42', $result->getSubject());
        self::assertSame('acme', $result->getTenant());

        $stored = $this->store->find(HashedToken::hashOf($created->getRefreshToken()));
        self::assertNotNull($stored);
        self::assertSame(TokenType::Refresh, $stored->getType());
        self::assertInstanceOf(SessionInterface::class, $created->getSession());

        $hash = $this->services->hasher()->hash('secret');
        self::assertTrue($this->services->hasher()->verify('secret', $hash));
    }

    public function testFromStoreDefaultsToArgon2idHasher(): void
    {
        $services = AuthServices::fromStore($this->store, self::KEY);

        self::assertStringStartsWith('$argon2id$', $services->hasher()->hash('secret'));
    }

    public function testSubjectIsAcceptedAsQualifiedStringOrObject(): void
    {
        $sessions = new SessionManager($this->store, self::KEY);

        $fromString = $sessions->create('service:billing');
        $fromObject = $sessions->create(Subject::from('billing', 'service'));

        self::assertSame('service:billing', $fromString->getSession()->getSubject());
        self::assertSame('service:billing', $fromObject->getSession()->getSubject());
        self::assertSame('user:7', $sessions->create('7')->getSession()->getSubject());
    }

    public function testRefreshAndInvalidateWorkThroughTheInterface(): void
    {
        $sessions = $this->services->sessions();
        $created = $sessions->create('user:42');

        $refreshed = $sessions->refresh($created->getRefreshToken());
        self::assertSame('user:42', $refreshed->getSession()->getSubject());

        $sessions->invalidateAll('user:42');
        $this->expectException(\JardisSupport\Auth\Exception\AuthenticationException::class);
        $sessions->refresh($refreshed->getRefreshToken());
    }

    public function testIssuedTokenExposesGetters(): void
    {
        $issued = $this->services->tokenIssuer()->issue(TokenType::Invitation, 'user:5', 3600, ['role' => 'member']);

        self::assertInstanceOf(IssuedToken::class, $issued);
        self::assertSame($issued->plain, $issued->getPlain());
        self::assertSame(HashedToken::hashOf($issued->getPlain()), $issued->getHashed()->getHash());
        self::assertSame('user:5', $issued->getHashed()->getSubject());
        self::assertSame(TokenType::Invitation, $issued->getHashed()->getType());
    }

    public function testSessionResultExposesGetters(): void
    {
        $created = (new SessionManager($this->store, self::KEY))->create('user:1');

        self::assertInstanceOf(SessionResult::class, $created);
        self::assertSame($created->accessToken, $created->getAccessToken());
        self::assertSame($created->refreshToken, $created->getRefreshToken());
        self::assertSame($created->session, $created->getSession());
    }

    public function testPeekLeavesTheTokenUnconsumedAndRedeemConsumesIt(): void
    {
        $store = new CountingTokenStore();
        $issuer = new TokenIssuer($store);
        $redeemer = new TokenRedeemer($store);
        $issued = $issuer->issue(TokenType::Invitation, 'user:5', 3600, ['role' => 'member']);

        $peeked = $redeemer->peek($issued->plain, TokenType::Invitation);
        $peekedAgain = $redeemer->peek($issued->plain, TokenType::Invitation);

        self::assertSame(0, $store->revokes);
        self::assertSame('user:5', $peeked->getSubject());
        self::assertSame(['role' => 'member'], $peekedAgain->getClaims());
        self::assertFalse($store->find($issued->hashed->hash)?->isRevoked());

        $redeemed = $redeemer->redeem($issued->plain, TokenType::Invitation);

        self::assertSame(1, $store->revokes);
        self::assertSame('user:5', $redeemed->getSubject());
        $this->expectException(TokenRevokedException::class);
        $redeemer->peek($issued->plain, TokenType::Invitation);
    }

    public function testPeekRejectsUnknownAndWrongTypeWithoutRevoking(): void
    {
        $store = new CountingTokenStore();
        $redeemer = new TokenRedeemer($store);
        $issued = (new TokenIssuer($store))->issue(TokenType::Invitation, 'user:5', 3600);

        try {
            $redeemer->peek('never-issued', TokenType::Invitation);
            self::fail('expected InvalidCredentialException');
        } catch (InvalidCredentialException) {
        }
        try {
            $redeemer->peek($issued->plain, TokenType::PasswordReset);
            self::fail('expected InvalidCredentialException');
        } catch (InvalidCredentialException) {
        }

        self::assertSame(0, $store->revokes);
    }

    public function testPeekOfExpiredTokenThrows(): void
    {
        $store = new InMemoryTokenStore();
        $issued = (new TokenIssuer($store))->issue(TokenType::Invitation, 'user:5', 1);
        $store->store(new HashedToken(
            hash: $issued->hashed->hash,
            type: TokenType::Invitation,
            subject: 'user:5',
            claims: [],
            expiresAt: new \DateTimeImmutable('-1 hour'),
            createdAt: new \DateTimeImmutable('-2 hours'),
        ));

        $this->expectException(TokenExpiredException::class);
        (new TokenRedeemer($store))->peek($issued->plain, TokenType::Invitation);
    }

    public function testRoleClaimOfSignedTokenReachesTheResult(): void
    {
        $created = $this->services->sessions()->create('user:42', [SessionClaim::TENANT => 'acme', SessionClaim::ROLE => 'admin']);

        $result = (new SignedTokenAuthenticator(self::KEY))->authenticate(Credential::token($created->getAccessToken()));

        self::assertInstanceOf(RoleAwareAuthResultInterface::class, $result);
        self::assertSame('admin', $result->getRole());
    }

    public function testMissingRoleClaimYieldsNull(): void
    {
        $created = $this->services->sessions()->create('user:42', [SessionClaim::TENANT => 'acme']);

        $result = (new SignedTokenAuthenticator(self::KEY))->authenticate(Credential::token($created->getAccessToken()));

        self::assertTrue($result->isSuccess());
        self::assertNull($result->getRole());
        self::assertNull(\JardisSupport\Auth\Data\TenantAuthResult::failure('x')->getRole());
    }

    public function testRoleClaimOfStoredTokenReachesTheResult(): void
    {
        $issued = $this->services->tokenIssuer()->issue(
            TokenType::ApiKey,
            'service:ci',
            3600,
            [SessionClaim::TENANT => 'acme', SessionClaim::ROLE => 'reader'],
        );

        $result = (new TokenAuthenticator($this->store, expectedType: TokenType::ApiKey))
            ->authenticate(Credential::token($issued->getPlain()));

        self::assertTrue($result->isSuccess());
        self::assertSame('reader', $result->getRole());
    }

    public function testPasswordAuthenticatorWorksWithTheBundleSessionManager(): void
    {
        $hasher = $this->services->hasher();
        $authenticator = new PasswordAuthenticator(
            $hasher,
            $this->services->sessions(),
            new FakeUserLookup('a@example.com', $hasher->hash('secret'), 'user:9', [SessionClaim::ROLE => 'admin']),
        );

        $result = $authenticator->authenticate(Credential::password('a@example.com', 'secret'));

        self::assertTrue($result->isSuccess());
        self::assertSame('user:9', $result->getSubject());
        self::assertNotNull($result->session);
        self::assertSame('admin', $result->session->metadata[SessionClaim::ROLE]);
        self::assertNotEmpty($result->accessToken);
    }

    public function testPasswordAuthenticatorAcceptsAForeignSessionManagerInterface(): void
    {
        $foreign = new class implements SessionManagerInterface {
            public ?string $subject = null;

            public function create(string $subject, array $claims = []): SessionResultInterface
            {
                $this->subject = $subject;

                return new class ($subject) implements SessionResultInterface {
                    public function __construct(private readonly string $subject)
                    {
                    }

                    public function getAccessToken(): string
                    {
                        return 'access';
                    }

                    public function getRefreshToken(): string
                    {
                        return 'refresh';
                    }

                    public function getSession(): SessionInterface
                    {
                        return new class ($this->subject) implements SessionInterface {
                            public function __construct(private readonly string $subject)
                            {
                            }

                            public function getSubject(): string
                            {
                                return $this->subject;
                            }

                            public function getTokenHash(): string
                            {
                                return 'hash';
                            }

                            public function getExpiresAt(): ?\DateTimeImmutable
                            {
                                return null;
                            }

                            public function isExpired(): bool
                            {
                                return false;
                            }

                            public function getMetadata(): array
                            {
                                return ['k' => 'v'];
                            }
                        };
                    }
                };
            }

            public function refresh(string $refreshToken): SessionResultInterface
            {
                throw new \LogicException('not used');
            }

            public function invalidateByReference(string $sessionReference): void
            {
            }

            public function invalidateAll(string $subject): void
            {
            }
        };
        $hasher = $this->services->hasher();
        $authenticator = new PasswordAuthenticator(
            $hasher,
            $foreign,
            new FakeUserLookup('a@example.com', $hasher->hash('secret'), 'user:9'),
        );

        $result = $authenticator->authenticate(Credential::password('a@example.com', 'secret'));

        self::assertTrue($result->isSuccess());
        self::assertSame('user:9', $foreign->subject);
        self::assertSame('access', $result->accessToken);
        self::assertSame('refresh', $result->refreshToken);
        self::assertSame('hash', $result->session?->tokenHash);
        self::assertSame(['k' => 'v'], $result->session?->metadata);
    }
}
