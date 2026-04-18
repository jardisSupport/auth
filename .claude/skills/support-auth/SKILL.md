---
name: support-auth
description: Session management, password hashing, RBAC, password authentication with events.
user-invocable: false
---

# AUTH_COMPONENT_SKILL
> `jardissupport/auth` | NS: `JardisSupport\Auth` | No HTTP, no JWT, no framework coupling | PHP 8.3+

## ARCHITECTURE
```
SessionManager        create/refresh/invalidate sessions → SessionResult + events
PasswordAuthenticator lookup user → verify password → create session → AuthenticationResult
PasswordHasher        Argon2id/bcrypt via password_hash() builtins
Guard                 RBAC permission check against immutable Policy
```
All orchestrators in `src/` root. Handlers in `src/Handler/{Category}/` as invokables bound via `->__invoke(...)`.

## API / SIGNATURES

### SessionManager
```php
new SessionManager(TokenStoreInterface $tokenStore, int $accessTokenTtl, int $refreshTokenTtl)

$sm->create(Subject $subject, array $claims = []): SessionResult
    // Returns: SessionResult{session, accessToken, refreshToken, events=[SessionCreated]}
$sm->refresh(string $refreshTokenValue): SessionResult
    // Returns: events=[SessionCreated, SessionRefreshed]
$sm->invalidate(Session $session): SessionInvalidated
$sm->invalidateAll(string $subjectString): AllSessionsInvalidated
```

### PasswordHasher
```php
PasswordHasher::argon2id(int $memoryCost = ..., int $timeCost = ..., int $threads = ...): self
PasswordHasher::bcrypt(int $cost = 12): self

$hasher->hash(string $password): string
$hasher->verify(string $password, string $hash): bool
$hasher->needsRehash(string $hash): bool
```

### Guard
```php
new Guard(Policy $policy)

$guard->check(SessionInterface $session, string $permission): bool
$guard->authorize(SessionInterface $session, string $permission): void  // throws UnauthorizedException
// metadata['role'] accepts string or string[] — first match wins
```

### PasswordAuthenticator
```php
new PasswordAuthenticator(
    PasswordHasherInterface $hasher,
    SessionManager $sessionManager,
    Closure $userLookup  // fn(string $id): ?array{hash, subject: Subject, claims: array}
)
$auth->authenticate(Credential $credential): AuthenticationResult
// AuthenticationResult->isSuccess(), ->session, ->accessToken, ->events
// Events on success: [SessionCreated, AuthenticationSucceeded]
// Events on failure: [AuthenticationFailed]
```

## DATA CLASSES (`src/Data/`)

| Class | Key fields / notes |
|-------|-------------------|
| `Session` | readonly — `subject`, `tokenHash`, `createdAt`, `expiresAt`, `metadata` |
| `SessionResult` | readonly — `session`, `accessToken`, `refreshToken`, `events: list<object>` |
| `AuthResult` | readonly — `::success()` / `::failure()` factories, `subject: Subject`, `reason` |
| `AuthenticationResult` | readonly, implements `AuthResultInterface` — wraps `AuthResult` + session + tokens + events |
| `Subject` | readonly — `id`, `type`, `toString()` → `"type:id"`, `equals()` |
| `Credential` | readonly — `::password()`, `::apiKey()`, `::token()` |
| `Token` | readonly — `::create(TokenType)`, `expiresIn()`, `forSubject()`, `withClaims()`, `hash()` → `HashedToken` |
| `HashedToken` | readonly, implements `HashedTokenInterface` — SHA-256 hash, `revoked`, `withRevoked()` |
| `Permission` | readonly — `::from("resource:action")`, `matches()`, wildcard support |
| `Policy` | readonly — `::fromArray()` or `PolicyBuilder`, `isAllowed(role, permission)`, `getRoles()` |
| `PolicyBuilder` | mutable — `role()->allow()->deny()->includes()->build()` |

## EVENTS (`src/Data/Event/`)
Plain readonly data objects — no interface, no dispatcher dependency. Caller dispatches.

| Event | Fields |
|-------|--------|
| `AuthenticationSucceeded` | `subject`, `timestamp` |
| `AuthenticationFailed` | `credentialType`, `reason`, `timestamp` |
| `SessionCreated` | `subject`, `tokenHash`, `timestamp` |
| `SessionRefreshed` | `subject`, `oldTokenHash`, `newTokenHash`, `timestamp` |
| `SessionInvalidated` | `subject`, `tokenHash`, `timestamp` |
| `AllSessionsInvalidated` | `subject`, `timestamp` |

## EXCEPTIONS (`src/Exception/`)
| Exception | Notes |
|-----------|-------|
| `AuthenticationException` | base, extends `RuntimeException` |
| `InvalidCredentialException` | extends `AuthenticationException` |
| `TokenExpiredException` | extends `AuthenticationException` |
| `TokenRevokedException` | extends `AuthenticationException` |
| `UnauthorizedException` | extends `RuntimeException`, NOT `AuthenticationException` |

## CONTRACTS (`jardissupport/contract`)
| Interface | Methods |
|-----------|---------|
| `TokenStoreInterface` | `store`, `find`, `revoke`, `revokeAllForSubject`, `deleteExpired` — **consumer must implement** |
| `PasswordHasherInterface` | `hash`, `verify`, `needsRehash` |
| `GuardInterface` | `check`, `authorize` |
| `AuthenticatorInterface` | `authenticate(CredentialInterface): AuthResultInterface` |
| `SessionInterface` | `getSubject`, `getTokenHash`, `isExpired`, `getMetadata` |
| `HashedTokenInterface` | `getHash`, `getType`, `getSubject`, `getClaims`, `getExpiresAt`, `getCreatedAt`, `isExpired`, `isRevoked` |
| `CredentialInterface` | `getType`, `getValue`, `getIdentifier` |
| `AuthResultInterface` | `isSuccess`, `getSubject`, `getReason` |
| `TokenType` (enum) | `Access`, `Refresh`, `ApiKey`, `Verification`, `PasswordReset` |
| `CredentialType` (enum) | `Password`, `ApiKey`, `Token` |

## USAGE — RBAC
```php
$policy = Policy::create()
    ->role('admin')->allow('*')
    ->role('editor')->allow('article:read', 'article:write')->deny('article:delete')
    ->role('moderator')->includes('editor')->allow('comment:delete')
    ->build();

$guard = new Guard($policy);
$guard->check($session, 'article:write');     // bool
$guard->authorize($session, 'article:write'); // void or UnauthorizedException
```

## RULES
- Events created and returned, never dispatched internally. Public error messages stay generic; details only in Events.
- `deny` overrides `allow`; role inheritance via `includes()`.
- `tests/Support/` for fakes (e.g. `InMemoryTokenStore`). Test paths mirror `src/`.
