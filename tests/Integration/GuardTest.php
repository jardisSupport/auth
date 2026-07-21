<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Tests\Integration;

use DateTimeImmutable;
use JardisSupport\Auth\Guard;
use JardisSupport\Auth\Data\Policy;
use JardisSupport\Auth\Data\Session;
use JardisSupport\Auth\Exception\UnauthorizedException;
use PHPUnit\Framework\TestCase;

final class GuardTest extends TestCase
{
    private Guard $guard;

    protected function setUp(): void
    {
        $policy = Policy::create()
            ->role('editor')
            ->allow('article:read', 'article:write')
            ->role('moderator')
            ->allow('comment:delete', 'comment:read')
            ->role('viewer')
            ->allow('article:read', 'comment:read')
            ->build();

        $this->guard = new Guard($policy);
    }

    /**
     * @param string|list<string>|null $role
     */
    private function buildSession(string $subject, string|array|null $role): Session
    {
        $metadata = $role !== null ? ['role' => $role] : [];

        return new Session(
            subject: $subject,
            tokenHash: hash('sha256', $subject . random_bytes(8)),
            createdAt: new DateTimeImmutable(),
            expiresAt: null,
            metadata: $metadata,
        );
    }

    // --- Single Role ---

    public function testCheckWithAllowedRoleReturnsTrue(): void
    {
        // Arrange
        $session = $this->buildSession('user:1', 'editor');

        // Act + Assert
        self::assertTrue($this->guard->check($session, 'article:write'));
    }

    public function testCheckWithDisallowedRoleReturnsFalse(): void
    {
        // Arrange
        $session = $this->buildSession('user:2', 'viewer');

        // Act + Assert
        self::assertFalse($this->guard->check($session, 'article:write'));
    }

    public function testAuthorizeWithAllowedRoleDoesNotThrow(): void
    {
        // Arrange
        $session = $this->buildSession('user:1', 'editor');

        // Act + Assert
        $this->expectNotToPerformAssertions();
        $this->guard->authorize($session, 'article:read');
    }

    public function testAuthorizeWithDisallowedRoleThrowsUnauthorizedException(): void
    {
        // Arrange
        $session = $this->buildSession('user:2', 'viewer');

        $this->expectException(UnauthorizedException::class);
        $this->expectExceptionMessage('Access denied for permission: article:write');

        // Act
        $this->guard->authorize($session, 'article:write');
    }

    public function testCheckWithNoRoleReturnsFalse(): void
    {
        // Arrange
        $session = $this->buildSession('user:3', null);

        // Act + Assert
        self::assertFalse($this->guard->check($session, 'article:read'));
    }

    public function testAuthorizeWithNoRoleThrowsUnauthorizedException(): void
    {
        // Arrange
        $session = $this->buildSession('user:3', null);

        $this->expectException(UnauthorizedException::class);

        // Act
        $this->guard->authorize($session, 'article:read');
    }

    public function testCheckWithUnknownRoleReturnsFalse(): void
    {
        // Arrange
        $session = $this->buildSession('user:4', 'superadmin');

        // Act + Assert
        self::assertFalse($this->guard->check($session, 'article:read'));
    }

    // --- Multi-Role ---

    public function testCheckWithMultiRoleWhenFirstRoleMatchesReturnsTrue(): void
    {
        // Arrange
        $session = $this->buildSession('user:1', ['editor', 'viewer']);

        // Act + Assert
        self::assertTrue($this->guard->check($session, 'article:write'));
    }

    public function testCheckWithMultiRoleWhenSecondRoleMatchesReturnsTrue(): void
    {
        // Arrange
        $session = $this->buildSession('user:1', ['viewer', 'moderator']);

        // Act + Assert
        self::assertTrue($this->guard->check($session, 'comment:delete'));
    }

    public function testCheckWithMultiRoleWhenNoRoleMatchesReturnsFalse(): void
    {
        // Arrange
        $session = $this->buildSession('user:1', ['viewer']);

        // Act + Assert
        self::assertFalse($this->guard->check($session, 'article:write'));
    }

    public function testCheckWithEmptyRolesArrayReturnsFalse(): void
    {
        // Arrange
        $session = $this->buildSession('user:1', []);

        // Act + Assert
        self::assertFalse($this->guard->check($session, 'article:read'));
    }

    public function testCheckWithMultiRoleSkipsNonStringEntries(): void
    {
        // Arrange
        $metadata = ['role' => ['editor', 42, null, 'viewer']];
        $session = new Session(
            subject: 'user:1',
            tokenHash: hash('sha256', 'test' . random_bytes(8)),
            createdAt: new DateTimeImmutable(),
            expiresAt: null,
            metadata: $metadata,
        );

        // Act + Assert
        self::assertTrue($this->guard->check($session, 'article:write'));
    }

    public function testAuthorizeWithMultiRoleWhenAnyRoleMatchesDoesNotThrow(): void
    {
        // Arrange
        $session = $this->buildSession('user:1', ['viewer', 'moderator']);

        // Act + Assert
        $this->expectNotToPerformAssertions();
        $this->guard->authorize($session, 'comment:delete');
    }

    public function testCheckWithMultiRoleUsesFirstMatchingRole(): void
    {
        // Arrange — both editor and viewer have article:read
        $session = $this->buildSession('user:1', ['editor', 'viewer']);

        // Act + Assert
        self::assertTrue($this->guard->check($session, 'article:read'));
    }
}
