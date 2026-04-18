<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Tests\Integration\Data;

use JardisSupport\Auth\Data\Subject;
use PHPUnit\Framework\TestCase;

final class SubjectTest extends TestCase
{
    // --- Subject::from() ---

    public function testFromCreatesSubjectWithGivenId(): void
    {
        // Arrange & Act
        $subject = Subject::from('42');

        // Assert
        $this->assertSame('42', $subject->id);
    }

    public function testFromCreatesSubjectWithDefaultTypeUser(): void
    {
        // Arrange & Act
        $subject = Subject::from('42');

        // Assert
        $this->assertSame('user', $subject->type);
    }

    public function testFromCreatesSubjectWithExplicitType(): void
    {
        // Arrange & Act
        $subject = Subject::from('svc-1', 'service');

        // Assert
        $this->assertSame('service', $subject->type);
    }

    public function testFromCreatesSubjectWithCustomTypeAndId(): void
    {
        // Arrange & Act
        $subject = Subject::from('org-99', 'organization');

        // Assert
        $this->assertSame('org-99', $subject->id);
        $this->assertSame('organization', $subject->type);
    }

    // --- Subject::equals() ---

    public function testEqualsReturnsTrueForSameIdAndType(): void
    {
        // Arrange
        $a = Subject::from('42', 'user');
        $b = Subject::from('42', 'user');

        // Act & Assert
        $this->assertTrue($a->equals($b));
    }

    public function testEqualsReturnsFalseForDifferentId(): void
    {
        // Arrange
        $a = Subject::from('42', 'user');
        $b = Subject::from('99', 'user');

        // Act & Assert
        $this->assertFalse($a->equals($b));
    }

    public function testEqualsReturnsFalseForDifferentType(): void
    {
        // Arrange
        $a = Subject::from('42', 'user');
        $b = Subject::from('42', 'service');

        // Act & Assert
        $this->assertFalse($a->equals($b));
    }

    public function testEqualsReturnsFalseForDifferentIdAndType(): void
    {
        // Arrange
        $a = Subject::from('42', 'user');
        $b = Subject::from('99', 'service');

        // Act & Assert
        $this->assertFalse($a->equals($b));
    }

    public function testEqualsIsSymmetric(): void
    {
        // Arrange
        $a = Subject::from('42', 'user');
        $b = Subject::from('42', 'user');

        // Act & Assert
        $this->assertSame($a->equals($b), $b->equals($a));
    }

    // --- Subject::toString() ---

    public function testToStringReturnsTypePrefixedId(): void
    {
        // Arrange
        $subject = Subject::from('42', 'user');

        // Act & Assert
        $this->assertSame('user:42', $subject->toString());
    }

    public function testToStringWithDefaultTypeReturnsUserPrefix(): void
    {
        // Arrange
        $subject = Subject::from('123');

        // Act & Assert
        $this->assertSame('user:123', $subject->toString());
    }

    public function testToStringWithCustomTypeReturnsCorrectFormat(): void
    {
        // Arrange
        $subject = Subject::from('svc-7', 'service');

        // Act & Assert
        $this->assertSame('service:svc-7', $subject->toString());
    }
}
