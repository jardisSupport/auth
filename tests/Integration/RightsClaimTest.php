<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Tests\Integration;

use JardisSupport\Auth\Data\Credential;
use JardisSupport\Auth\Data\TenantAuthResult;
use JardisSupport\Auth\SessionManager;
use JardisSupport\Auth\SignedTokenAuthenticator;
use JardisSupport\Auth\Tests\Support\InMemoryTokenStore;
use JardisSupport\Auth\TokenAuthenticator;
use JardisSupport\Auth\TokenIssuer;
use JardisSupport\Contract\Auth\RightsAwareAuthResultInterface;
use JardisSupport\Contract\Auth\SessionClaim;
use JardisSupport\Contract\Auth\TokenType;
use PHPUnit\Framework\TestCase;

/** The claim `rights` surfaces as `getRights()` of the authentication result, for stored and signed tokens. */
final class RightsClaimTest extends TestCase
{
    private const KEY = 'abcdefghijklmnopqrstuvwxyz012345';

    private InMemoryTokenStore $store;

    protected function setUp(): void
    {
        $this->store = new InMemoryTokenStore();
    }

    public function testStoredTokenWithRightsClaimCarriesTheRights(): void
    {
        $result = $this->authenticateStored([SessionClaim::RIGHTS => ['sales.process:x', 'sales.query:*']]);

        self::assertInstanceOf(RightsAwareAuthResultInterface::class, $result);
        self::assertTrue($result->isSuccess());
        self::assertSame(['sales.process:x', 'sales.query:*'], $result->getRights());
    }

    public function testStoredTokenWithoutRightsClaimYieldsEmptyList(): void
    {
        $result = $this->authenticateStored([SessionClaim::TENANT => 'acme']);

        self::assertTrue($result->isSuccess());
        self::assertSame([], $result->getRights());
    }

    public function testSignedTokenWithRightsClaimCarriesTheRights(): void
    {
        $result = $this->authenticateSigned([SessionClaim::RIGHTS => ['*']]);

        self::assertInstanceOf(RightsAwareAuthResultInterface::class, $result);
        self::assertTrue($result->isSuccess());
        self::assertSame(['*'], $result->getRights());
    }

    public function testSignedTokenWithoutRightsClaimYieldsEmptyList(): void
    {
        $result = $this->authenticateSigned([SessionClaim::TENANT => 'acme']);

        self::assertTrue($result->isSuccess());
        self::assertSame([], $result->getRights());
    }

    /** @return array<string, array{mixed}> */
    public static function malformedRights(): array
    {
        return [
            'string' => ['sales.process:x'],
            'map' => [['a' => 'sales.process:x']],
            'mixed list' => [['sales.process:x', 5]],
            'nested' => [[['sales.process:x']]],
            'null' => [null],
            'int' => [7],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('malformedRights')]
    public function testOnlyAListOfStringsCountsStored(mixed $claim): void
    {
        self::assertSame([], $this->authenticateStored([SessionClaim::RIGHTS => $claim])->getRights());
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('malformedRights')]
    public function testOnlyAListOfStringsCountsSigned(mixed $claim): void
    {
        self::assertSame([], $this->authenticateSigned([SessionClaim::RIGHTS => $claim])->getRights());
    }

    public function testFailureResultHasNoRights(): void
    {
        $result = TenantAuthResult::failure('Invalid token');

        self::assertFalse($result->isSuccess());
        self::assertSame([], $result->getRights());
    }

    public function testSuccessFactoryTakesRightsAsLastArgument(): void
    {
        $result = TenantAuthResult::success('user:1', 'acme', 'ref', 'admin', ['a:b']);

        self::assertSame(['a:b'], $result->getRights());
        self::assertSame('admin', $result->getRole());
    }

    /** @param array<string, mixed> $claims */
    private function authenticateStored(array $claims): TenantAuthResult
    {
        $issued = (new TokenIssuer($this->store))->issue(TokenType::ApiKey, 'service:ci', 3600, $claims);

        return (new TokenAuthenticator($this->store, expectedType: TokenType::ApiKey))
            ->authenticate(Credential::token($issued->plain));
    }

    /** @param array<string, mixed> $claims */
    private function authenticateSigned(array $claims): TenantAuthResult
    {
        $created = (new SessionManager($this->store, self::KEY))->create('user:42', $claims);

        return (new SignedTokenAuthenticator(self::KEY))->authenticate(Credential::token($created->accessToken));
    }
}
