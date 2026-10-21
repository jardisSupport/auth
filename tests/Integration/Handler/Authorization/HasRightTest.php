<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Tests\Integration\Handler\Authorization;

use JardisSupport\Auth\Handler\Authorization\HasRight;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class HasRightTest extends TestCase
{
    /** @return array<string, array{list<string>, string, bool}> */
    public static function matrix(): array
    {
        return [
            'wildcard grants anything' => [['*'], 'any.thing:at-all', true],
            'exact right' => [['sales.process:x'], 'sales.process:x', true],
            'empty list' => [[], 'sales.process:x', false],
            'action wildcard' => [['sales.process:*'], 'sales.process:y', true],
            'other right' => [['a:b'], 'c:d', false],
        ];
    }

    /** @param list<string> $rights */
    #[DataProvider('matrix')]
    public function testMatrix(array $rights, string $right, bool $expected): void
    {
        self::assertSame($expected, (new HasRight())($rights, $right));
    }

    public function testSecondRightOfTheListGrants(): void
    {
        self::assertTrue((new HasRight())(['a:b', 'c:*'], 'c:d'));
    }

    public function testUnparsableRequiredRightThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        (new HasRight())(['*'], 'no-colon');
    }

    public function testUnparsableGrantedRightThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        (new HasRight())(['broken'], 'a:b');
    }
}
