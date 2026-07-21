<?php

declare(strict_types=1);

namespace JardisSupport\Auth\Handler\Authorization;

use Closure;
use JardisSupport\Auth\Exception\UnauthorizedException;
use JardisSupport\Contract\Auth\SessionInterface;

/** Enforces a permission check on a session, throwing UnauthorizedException when access is denied. */
final class AuthorizePermission
{
    /**
     * @param Closure(SessionInterface, string): bool $checkPermission
     */
    public function __construct(
        private readonly Closure $checkPermission,
    ) {
    }

    public function __invoke(SessionInterface $session, string $permission): void
    {
        if (!($this->checkPermission)($session, $permission)) {
            throw new UnauthorizedException(
                'Access denied for permission: ' . $permission
            );
        }
    }
}
