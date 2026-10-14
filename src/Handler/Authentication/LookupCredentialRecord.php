<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Handler\Authentication;

use JardisSupport\Auth\Data\Subject;
use JardisSupport\Contract\Auth\UserLookupInterface;

/** Looks up a user's credential record via a `UserLookupInterface` and maps it to the array form the authenticator consumes. */
final class LookupCredentialRecord
{
    public function __construct(
        private readonly UserLookupInterface $userLookup,
    ) {
    }

    /**
     * @return ?array{hash: string, subject: Subject, claims: array<string, mixed>}
     */
    public function __invoke(string $identifier): ?array
    {
        $record = $this->userLookup->lookup($identifier);

        if ($record === null) {
            return null;
        }

        return [
            'hash' => $record->getPasswordHash(),
            'subject' => Subject::parse($record->getSubject()),
            'claims' => $record->getClaims(),
        ];
    }
}
