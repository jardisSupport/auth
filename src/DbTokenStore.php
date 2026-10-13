<?php

declare(strict_types=1);

namespace JardisSupport\Auth;

use Closure;
use JardisSupport\Auth\Handler\TokenStore\AssertTableName;
use JardisSupport\Auth\Handler\TokenStore\DeleteExpiredTokens;
use JardisSupport\Auth\Handler\TokenStore\ExecuteQuery;
use JardisSupport\Auth\Handler\TokenStore\FindToken;
use JardisSupport\Auth\Handler\TokenStore\FormatUtcTimestamp;
use JardisSupport\Auth\Handler\TokenStore\RevokeSubjectTokens;
use JardisSupport\Auth\Handler\TokenStore\RevokeToken;
use JardisSupport\Auth\Handler\TokenStore\StoreToken;
use JardisSupport\Contract\Auth\HashedTokenInterface;
use JardisSupport\Contract\Auth\TokenStoreInterface;
use JardisSupport\Contract\DbConnection\DbConnectionInterface;

/**
 * Orchestrates token persistence on a database connection via jardissupport/dbquery.
 *
 * Stores only the SHA-256 hash of a token. The table DDL ships in resources/sql/<driver>.sql.
 */
final class DbTokenStore implements TokenStoreInterface
{
    private readonly Closure $storeToken;
    private readonly Closure $findToken;
    private readonly Closure $revokeToken;
    private readonly Closure $revokeSubjectTokens;
    private readonly Closure $deleteExpiredTokens;

    public function __construct(DbConnectionInterface $connection, string $table = 'auth_tokens')
    {
        $table = (new AssertTableName())->__invoke($table);
        $executeQuery = (new ExecuteQuery($connection))->__invoke(...);
        $formatTimestamp = (new FormatUtcTimestamp())->__invoke(...);

        $this->storeToken = (new StoreToken($executeQuery, $formatTimestamp, $table))->__invoke(...);
        $this->findToken = (new FindToken($executeQuery, $table))->__invoke(...);
        $this->revokeToken = (new RevokeToken($executeQuery, $table))->__invoke(...);
        $this->revokeSubjectTokens = (new RevokeSubjectTokens($executeQuery, $table))->__invoke(...);
        $this->deleteExpiredTokens = (new DeleteExpiredTokens($executeQuery, $formatTimestamp, $table))->__invoke(...);
    }

    public function store(HashedTokenInterface $token): void
    {
        ($this->storeToken)($token);
    }

    public function find(string $hash): ?HashedTokenInterface
    {
        return ($this->findToken)($hash);
    }

    public function revoke(string $hash): void
    {
        ($this->revokeToken)($hash);
    }

    public function revokeAllForSubject(string $subject): void
    {
        ($this->revokeSubjectTokens)($subject);
    }

    public function deleteExpired(): int
    {
        return ($this->deleteExpiredTokens)();
    }
}
