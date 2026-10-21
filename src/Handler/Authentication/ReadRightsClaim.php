<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Handler\Authentication;

use JardisSupport\Contract\Auth\SessionClaim;

/** Reads the claim `SessionClaim::RIGHTS`: only a list of strings counts, anything else is no claim (`[]`). */
final class ReadRightsClaim
{
    /**
     * @param array<array-key, mixed> $claims
     * @return list<string>
     */
    public function __invoke(array $claims): array
    {
        $rights = $claims[SessionClaim::RIGHTS] ?? null;

        if (!is_array($rights) || !array_is_list($rights)) {
            return [];
        }

        foreach ($rights as $right) {
            if (!is_string($right)) {
                return [];
            }
        }

        return $rights;
    }
}
