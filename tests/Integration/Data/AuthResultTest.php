<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Tests\Integration\Data;

use JardisSupport\Auth\Data\AuthResult;
use JardisSupport\Auth\Data\Subject;
use PHPUnit\Framework\TestCase;

final class AuthResultTest extends TestCase
{
    // --- AuthResult::success() ---

    public function testSuccessSetsSuccessToTrue(): void
    {
        // Arrange
        $subject = Subject::from('42');

        // Act
        $result = AuthResult::success($subject);

        // Assert
        $this->assertTrue($result->success);
    }

    public function testSuccessSetsSubjectToGivenSubject(): void
    {
        // Arrange
        $subject = Subject::from('42', 'user');

        // Act
        $result = AuthResult::success($subject);

        // Assert
        $this->assertSame($subject, $result->subject);
    }

    public function testSuccessSetsReasonToNull(): void
    {
        // Arrange
        $subject = Subject::from('42');

        // Act
        $result = AuthResult::success($subject);

        // Assert
        $this->assertNull($result->reason);
    }

    public function testSuccessWithDifferentSubjectTypes(): void
    {
        // Arrange
        $subject = Subject::from('svc-1', 'service');

        // Act
        $result = AuthResult::success($subject);

        // Assert
        $this->assertTrue($result->success);
        $this->assertSame('svc-1', $result->subject?->id);
        $this->assertSame('service', $result->subject?->type);
    }

    // --- AuthResult::failure() ---

    public function testFailureSetsSuccessToFalse(): void
    {
        // Arrange & Act
        $result = AuthResult::failure('Invalid credentials');

        // Assert
        $this->assertFalse($result->success);
    }

    public function testFailureSetsSubjectToNull(): void
    {
        // Arrange & Act
        $result = AuthResult::failure('Invalid credentials');

        // Assert
        $this->assertNull($result->subject);
    }

    public function testFailureSetsReasonToGivenMessage(): void
    {
        // Arrange & Act
        $result = AuthResult::failure('Invalid credentials');

        // Assert
        $this->assertSame('Invalid credentials', $result->reason);
    }

    public function testFailureWithDifferentReasons(): void
    {
        // Arrange & Act
        $result = AuthResult::failure('Account locked');

        // Assert
        $this->assertFalse($result->success);
        $this->assertSame('Account locked', $result->reason);
    }

    public function testFailureReasonIsPreservedVerbatim(): void
    {
        // Arrange
        $reason = 'Token expired after 3600 seconds';

        // Act
        $result = AuthResult::failure($reason);

        // Assert
        $this->assertSame($reason, $result->reason);
    }
}
