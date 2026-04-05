<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Exception;

use RuntimeException;

/** Thrown when an authenticated subject lacks the required permission for an action. */
class UnauthorizedException extends RuntimeException
{
}
