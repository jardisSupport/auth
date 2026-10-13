<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Handler\TokenStore;

use DateTimeImmutable;
use DateTimeInterface;
use DateTimeZone;

/** Formats a point in time as UTC text 'Y-m-d H:i:s.u' (sortable, accepted by all supported dialects). */
final class FormatUtcTimestamp
{
    public function __invoke(DateTimeInterface $moment): string
    {
        return DateTimeImmutable::createFromInterface($moment)
            ->setTimezone(new DateTimeZone('UTC'))
            ->format('Y-m-d H:i:s.u');
    }
}
