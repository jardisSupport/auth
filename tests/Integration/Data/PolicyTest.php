<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Tests\Integration\Data;

use JardisSupport\Auth\Data\Policy;
use PHPUnit\Framework\TestCase;

final class PolicyTest extends TestCase
{
    public function testCreateReturnsBuilderAndBuildProducesPolicy(): void
    {
        // Arrange + Act
        $policy = Policy::create()
            ->role('editor')
            ->allow('article:read', 'article:write')
            ->build();

        // Assert
        self::assertContains('editor', $policy->getRoles());
    }

    public function testIsAllowedReturnsTrueForGrantedPermission(): void
    {
        // Arrange
        $policy = Policy::create()
            ->role('editor')
            ->allow('article:read', 'article:write')
            ->build();

        // Act + Assert
        self::assertTrue($policy->isAllowed('editor', 'article:read'));
        self::assertTrue($policy->isAllowed('editor', 'article:write'));
    }

    public function testIsAllowedReturnsFalseForNotGrantedPermission(): void
    {
        // Arrange
        $policy = Policy::create()
            ->role('editor')
            ->allow('article:read')
            ->build();

        // Act + Assert
        self::assertFalse($policy->isAllowed('editor', 'article:delete'));
    }

    public function testDenyOverridesAllow(): void
    {
        // Arrange
        $policy = Policy::create()
            ->role('restricted-editor')
            ->allow('article:*')
            ->deny('article:delete')
            ->build();

        // Act + Assert
        self::assertTrue($policy->isAllowed('restricted-editor', 'article:read'));
        self::assertTrue($policy->isAllowed('restricted-editor', 'article:write'));
        self::assertFalse($policy->isAllowed('restricted-editor', 'article:delete'));
    }

    public function testDenyWithWildcardDeniesAllPermissions(): void
    {
        // Arrange
        $policy = Policy::create()
            ->role('blocked')
            ->allow('*')
            ->deny('*')
            ->build();

        // Act + Assert
        self::assertFalse($policy->isAllowed('blocked', 'article:read'));
    }

    public function testHierarchicalRolesInheritPermissionsFromIncludedRole(): void
    {
        // Arrange
        $policy = Policy::create()
            ->role('viewer')
            ->allow('article:read')
            ->role('editor')
            ->allow('article:write')
            ->includes('viewer')
            ->build();

        // Act + Assert
        // editor erbt article:read von viewer
        self::assertTrue($policy->isAllowed('editor', 'article:read'));
        self::assertTrue($policy->isAllowed('editor', 'article:write'));
        // viewer hat kein write
        self::assertFalse($policy->isAllowed('viewer', 'article:write'));
    }

    public function testHierarchicalRolesDenyInParentOverridesInheritedAllow(): void
    {
        // Arrange
        $policy = Policy::create()
            ->role('viewer')
            ->allow('article:read')
            ->role('restricted')
            ->deny('article:read')
            ->includes('viewer')
            ->build();

        // Act + Assert
        self::assertFalse($policy->isAllowed('restricted', 'article:read'));
    }

    public function testIsAllowedReturnsFalseForUnknownRole(): void
    {
        // Arrange
        $policy = Policy::create()
            ->role('editor')
            ->allow('article:read')
            ->build();

        // Act + Assert
        self::assertFalse($policy->isAllowed('nonexistent', 'article:read'));
    }

    public function testGetRolesReturnsAllDefinedRoles(): void
    {
        // Arrange
        $policy = Policy::create()
            ->role('admin')
            ->allow('*')
            ->role('viewer')
            ->allow('article:read')
            ->build();

        // Act
        $roles = $policy->getRoles();

        // Assert
        self::assertCount(2, $roles);
        self::assertContains('admin', $roles);
        self::assertContains('viewer', $roles);
    }

    public function testAdminWithWildcardIsAllowedForAnyPermission(): void
    {
        // Arrange
        $policy = Policy::create()
            ->role('admin')
            ->allow('*')
            ->build();

        // Act + Assert
        self::assertTrue($policy->isAllowed('admin', 'article:read'));
        self::assertTrue($policy->isAllowed('admin', 'user:delete'));
        self::assertTrue($policy->isAllowed('admin', 'settings:write'));
    }
}
