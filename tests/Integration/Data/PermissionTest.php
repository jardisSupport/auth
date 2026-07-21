<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Tests\Integration\Data;

use InvalidArgumentException;
use JardisSupport\Auth\Data\Permission;
use PHPUnit\Framework\TestCase;

final class PermissionTest extends TestCase
{
    public function testFromWithResourceActionFormatCreatesPermission(): void
    {
        // Arrange + Act
        $permission = Permission::from('article:read');

        // Assert
        self::assertSame('article', $permission->resource);
        self::assertSame('read', $permission->action);
    }

    public function testFromWithWildcardCreatesWildcardPermission(): void
    {
        // Arrange + Act
        $permission = Permission::from('*');

        // Assert
        self::assertSame('*', $permission->resource);
        self::assertSame('*', $permission->action);
    }

    public function testFromWithInvalidFormatThrowsInvalidArgumentException(): void
    {
        // Arrange
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/format "resource:action" or "\*"/');

        // Act
        Permission::from('invalidpermission');
    }

    public function testMatchesWildcardPermissionMatchesAnyPermission(): void
    {
        // Arrange
        $wildcard = Permission::from('*');
        $other = Permission::from('article:delete');

        // Act + Assert
        self::assertTrue($wildcard->matches($other));
    }

    public function testMatchesResourceWildcardMatchesAnyActionOnSameResource(): void
    {
        // Arrange
        $resourceWildcard = Permission::from('article:*');
        $read = Permission::from('article:read');
        $delete = Permission::from('article:delete');
        $other = Permission::from('user:read');

        // Act + Assert
        self::assertTrue($resourceWildcard->matches($read));
        self::assertTrue($resourceWildcard->matches($delete));
        self::assertFalse($resourceWildcard->matches($other));
    }

    public function testMatchesExactPermissionMatchesOnlyItself(): void
    {
        // Arrange
        $permission = Permission::from('article:read');
        $same = Permission::from('article:read');
        $different = Permission::from('article:write');
        $otherResource = Permission::from('user:read');

        // Act + Assert
        self::assertTrue($permission->matches($same));
        self::assertFalse($permission->matches($different));
        self::assertFalse($permission->matches($otherResource));
    }

    public function testMatchesDifferentResourceReturnsFalse(): void
    {
        // Arrange
        $permission = Permission::from('article:read');
        $other = Permission::from('user:read');

        // Act + Assert
        self::assertFalse($permission->matches($other));
    }

    public function testEqualsReturnsTrueForSamePermission(): void
    {
        // Arrange
        $a = Permission::from('article:read');
        $b = Permission::from('article:read');

        // Act + Assert
        self::assertTrue($a->equals($b));
    }

    public function testEqualsReturnsFalseForDifferentPermission(): void
    {
        // Arrange
        $a = Permission::from('article:read');
        $b = Permission::from('article:write');

        // Act + Assert
        self::assertFalse($a->equals($b));
    }

    public function testToStringReturnsResourceColonActionFormat(): void
    {
        // Arrange
        $permission = Permission::from('article:read');

        // Act + Assert
        self::assertSame('article:read', $permission->toString());
    }

    public function testToStringReturnsAsteriskForWildcardPermission(): void
    {
        // Arrange
        $permission = Permission::from('*');

        // Act + Assert
        self::assertSame('*', $permission->toString());
    }
}
