<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Tests\Support;

use JardisSupport\Contract\Auth\CredentialRecordInterface;
use JardisSupport\Contract\Auth\UserLookupInterface;

/** In-memory `UserLookupInterface` fake: one account, found by its identifier. */
final class FakeUserLookup implements UserLookupInterface
{
    /**
     * @param array<string, mixed> $claims
     */
    public function __construct(
        private readonly string $identifier,
        private readonly string $hash,
        private readonly string $subject,
        private readonly array $claims = [],
    ) {
    }

    public function lookup(string $identifier): ?CredentialRecordInterface
    {
        if ($identifier !== $this->identifier) {
            return null;
        }

        $hash = $this->hash;
        $subject = $this->subject;
        $claims = $this->claims;

        return new class ($hash, $subject, $claims) implements CredentialRecordInterface {
            /**
             * @param array<string, mixed> $claims
             */
            public function __construct(
                private readonly string $hash,
                private readonly string $subject,
                private readonly array $claims,
            ) {
            }

            public function getPasswordHash(): string
            {
                return $this->hash;
            }

            public function getSubject(): string
            {
                return $this->subject;
            }

            public function getClaims(): array
            {
                return $this->claims;
            }
        };
    }
}
