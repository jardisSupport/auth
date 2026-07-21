<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Exception;

/** Thrown when a supplied credential (password, token) does not match the stored value. */
class InvalidCredentialException extends AuthenticationException
{
}
