<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Exception;

/** Thrown when a token is valid but its expiry time has passed. */
class TokenExpiredException extends AuthenticationException
{
}
