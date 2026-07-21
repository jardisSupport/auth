<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Exception;

/** Thrown when a token has been explicitly revoked before use. */
class TokenRevokedException extends AuthenticationException
{
}
