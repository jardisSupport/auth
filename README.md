# Jardis Auth

![Build Status](https://github.com/jardisSupport/auth/actions/workflows/ci.yml/badge.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE.md)
[![PHP Version](https://img.shields.io/badge/PHP-%3E%3D8.3-777BB4.svg)](https://www.php.net/)
[![PHPStan Level](https://img.shields.io/badge/PHPStan-Level%208-brightgreen.svg)](phpstan.neon)
[![PSR-12](https://img.shields.io/badge/Code%20Style-PSR--12-blue.svg)](phpcs.xml)

> Part of **[Jardis](https://jardis.io)** — the Domain-Driven Design platform for PHP. You model your domain; Jardis generates the production-ready hexagonal code (DTOs, Command/Query handlers, repositories, persistence). This package is part of the open-source foundation that generated code runs on.

**Authentication and authorization without framework coupling.** A focused RBAC for PHP covering opaque tokens, session management, password hashing, and role-based access control — designed for DDD applications. No HTTP layer, no JWT, no third-party runtime dependencies beyond PHP built-ins and the Jardis packages `contracts` and `dbquery`. Pure support package.

---

## Why This Package?

- **Six classes to learn** — `SessionManager`, `PasswordHasher`, `Guard`, `PasswordAuthenticator`, `TokenAuthenticator`, `DbTokenStore`. Everything else is data
- **Opaque tokens** — server-side state, SHA-256 hashed storage, no JWT complexity
- **Token rotation** — automatic refresh with old-token revocation
- **RBAC as Value Objects** — policies are immutable, defined in code, not in a database
- **No third-party runtime dependencies** — PHP built-ins (`password_hash`, `random_bytes`, `hash`, `hash_equals`) plus the Jardis contract

---

## Installation

```bash
composer require jardissupport/auth
```

---

## Quick Start

### Create a Session

```php
use JardisSupport\Auth\SessionManager;
use JardisSupport\Auth\Data\Subject;

$sessionManager = new SessionManager($tokenStore);
$subject = Subject::from('user-42', 'user');

$result = $sessionManager->create($subject, ['role' => 'editor']);

$accessToken  = $result->accessToken;   // send to client
$refreshToken = $result->refreshToken;  // store securely on client
$session      = $result->session;       // use server-side

// Dispatch events (optional — use your EventDispatcher)
foreach ($result->events as $event) {
    $dispatcher->dispatch($event);
}
```

### Verify & Refresh Tokens

```php
use JardisSupport\Auth\Handler\Token\VerifyToken;
use JardisSupport\Auth\Data\TokenType;

// Verify an access token
$verifier = new VerifyToken();
$hash = hash('sha256', $accessToken);
$stored = $tokenStore->find($hash);
$verifier($accessToken, $stored, TokenType::Access);
// throws TokenExpiredException or TokenRevokedException

// Refresh — rotates tokens, revokes the old refresh token
$newResult = $sessionManager->refresh($refreshToken);
// $newResult->events contains SessionCreated + SessionRefreshed
```

### Hash & Verify Passwords

```php
use JardisSupport\Auth\PasswordHasher;

$hasher = PasswordHasher::argon2id();

// Registration
$hash = $hasher->hash('secret-password');

// Login
$hasher->verify('secret-password', $hash); // true

// Rehash check on every login
if ($hasher->needsRehash($hash)) {
    $newHash = $hasher->hash('secret-password');
    // update stored hash
}
```

### Authorize with RBAC

```php
use JardisSupport\Auth\Guard;
use JardisSupport\Auth\Data\Policy;

$policy = Policy::create()
    ->role('admin')->allow('*')
    ->role('editor')
        ->allow('article:read', 'article:write', 'article:publish')
        ->deny('article:delete')
    ->role('viewer')->allow('article:read')
    ->role('moderator')->includes('editor')->allow('comment:delete')
    ->build();

$guard = new Guard($policy);

$guard->check($session, 'article:publish');     // true/false
$guard->authorize($session, 'article:delete');  // throws UnauthorizedException

// Multi-role sessions — first matching role wins
$session = new Session(
    subject: 'user:42',
    tokenHash: $hash,
    createdAt: new DateTimeImmutable(),
    expiresAt: null,
    metadata: ['role' => ['editor', 'moderator']],
);
$guard->check($session, 'comment:delete');  // true (moderator has permission)
```

### Authenticate with Password

```php
use JardisSupport\Auth\PasswordAuthenticator;
use JardisSupport\Auth\Data\Credential;

$authenticator = new PasswordAuthenticator(
    $passwordHasher,
    $sessionManager,
    function (string $identifier): ?array {
        $user = $userRepository->findByEmail($identifier);
        if ($user === null) {
            return null;
        }
        return [
            'hash' => $user->passwordHash,
            'subject' => Subject::from($user->id, 'user'),
            'claims' => ['role' => $user->role],
        ];
    },
);

$credential = Credential::password('john@example.com', 'secret123');
$result = $authenticator->authenticate($credential);

if ($result->isSuccess()) {
    $session = $result->session;
    $accessToken = $result->accessToken;
}

// All events in one place: SessionCreated + AuthenticationSucceeded (or AuthenticationFailed)
foreach ($result->events as $event) {
    $dispatcher->dispatch($event);
}
```

### Invalidate Sessions

```php
// Single session (logout) — returns SessionInvalidated event
$event = $sessionManager->invalidate($session);

// All sessions for a subject (logout everywhere) — returns AllSessionsInvalidated event
$event = $sessionManager->invalidateAll('user:user-42');
```

---

## Token Store

`DbTokenStore` implements `TokenStoreInterface` on a `DbConnectionInterface` (`jardissupport/contracts`) using `jardissupport/dbquery` — no raw SQL, no own PDO. Only the SHA-256 hash of a token is stored, never the plain value.

```php
use JardisSupport\Auth\DbTokenStore;

$store = new DbTokenStore($connection);                 // table: auth_tokens
$store = new DbTokenStore($connection, 'my_tokens');    // custom table name (plain identifier)

$sessionManager = new SessionManager($store);
```

**Table DDL** ships with the package (one file per dialect, `auth_tokens`, timestamps in UTC):

| Dialect | File |
|---------|------|
| MySQL / MariaDB | `vendor/jardissupport/auth/resources/sql/mysql.sql` |
| PostgreSQL | `vendor/jardissupport/auth/resources/sql/pgsql.sql` |
| SQLite | `vendor/jardissupport/auth/resources/sql/sqlite.sql` |

Apply the file matching `$connection->getDriverName()` once in your migration/setup (all statements are `IF NOT EXISTS`). For another table name replace `auth_tokens` in the file.

Prefer your own store (Redis, ...)? Implement `TokenStoreInterface` yourself; an `InMemoryTokenStore` for tests lives in `tests/Support/`.

---

## Authenticate a Token (request → subject + tenant)

`TokenAuthenticator` resolves an access token to a verified session: a valid, non-revoked, non-expired token yields a successful `TenantAwareAuthResultInterface` with subject **and** tenant; any other token yields a failure with a reason.

```php
use JardisSupport\Auth\Data\Credential;
use JardisSupport\Auth\TokenAuthenticator;
use JardisSupport\Contract\Auth\RequestAttribute;

// The tenant is a claim of the access token, set when the session is created:
$session = $sessionManager->create(Subject::from('42'), ['tenant' => 'acme']);

$authenticator = new TokenAuthenticator($store);               // tenant claim: 'tenant'
$authenticator = new TokenAuthenticator($store, tenantClaim: 'org');

$result = $authenticator->authenticate(Credential::token($bearerToken));

if ($result->isSuccess()) {
    $request = $request
        ->withAttribute(RequestAttribute::SUBJECT, $result->getSubject())  // 'user:42'
        ->withAttribute(RequestAttribute::TENANT, $result->getTenant());   // 'acme' | null
} else {
    $result->getReason(); // 'Invalid token' | 'Token expired' | 'Token revoked' | 'Unsupported credential type'
}
```

Only `TokenType::Access` tokens are accepted by default (4th constructor argument changes that). The attribute names `RequestAttribute::SUBJECT` (`jardisSubject`) and `RequestAttribute::TENANT` (`jardisTenant`) live in `jardissupport/contracts` (>= 2.8.0).

---

## Password Hashing

```php
// Argon2id (default, recommended)
$hasher = PasswordHasher::argon2id(memoryCost: 65536, timeCost: 4, threads: 1);

// Bcrypt (fallback)
$hasher = PasswordHasher::bcrypt(cost: 12);

// Default constructor uses Argon2id
$hasher = new PasswordHasher();
```

---

## Error Handling

| Exception | When |
|-----------|------|
| `AuthenticationException` | Authentication failed (base class) |
| `TokenExpiredException` | Token has expired |
| `TokenRevokedException` | Token was revoked |
| `InvalidCredentialException` | Invalid credentials provided |
| `UnauthorizedException` | Insufficient permissions (RBAC) |

```php
use JardisSupport\Auth\Exception\TokenExpiredException;
use JardisSupport\Auth\Exception\UnauthorizedException;

try {
    $verifier($token, $storedToken, TokenType::Access);
} catch (TokenExpiredException $e) {
    // Token expired — client should use refresh token
}

try {
    $guard->authorize($session, 'admin:delete');
} catch (UnauthorizedException $e) {
    // Access denied
}
```

---

## Architecture

The user sees six orchestrators. Internally, each delegates to invokable handlers:

```
SessionManager (Orchestrator)
  ├── Handler/Session/CreateSession         create session + token pair + SessionCreated event
  ├── Handler/Session/RefreshSession        rotate tokens + SessionRefreshed event
  ├── Handler/Session/InvalidateSession     revoke single session + SessionInvalidated event
  └── Handler/Session/InvalidateAllSessions revoke all + AllSessionsInvalidated event

PasswordAuthenticator (Orchestrator)
  ├── Handler/Authentication/LookupUser      resolve user via $userLookup closure
  ├── Handler/Authentication/VerifyCredential verify password against hash
  └── Handler/Authentication/BuildAuthResult  assemble AuthenticationResult + events

TokenAuthenticator (Orchestrator)
  └── Handler/Authentication/AuthenticateToken  lookup → verify → subject + tenant claim → TenantAuthResult

DbTokenStore (Orchestrator)
  ├── Handler/TokenStore/StoreToken · FindToken · RevokeToken · RevokeSubjectTokens · DeleteExpiredTokens
  └── Handler/TokenStore/ExecuteQuery       dbquery builder → prepared statement on the connection

PasswordHasher (Orchestrator)
  ├── Handler/Password/HashPassword         hash via password_hash()
  ├── Handler/Password/VerifyPassword       verify via password_verify()
  └── Handler/Password/CheckRehash          check via password_needs_rehash()

Guard (Orchestrator)
  ├── Handler/Authorization/CheckPermission    check role(s) against policy
  └── Handler/Authorization/AuthorizePermission check + throw on failure

Data (Value Objects, Enums, Builder, Events)
  ├── Token, HashedToken, TokenType
  ├── Session, SessionResult
  ├── Subject, Credential, CredentialType, AuthResult, AuthenticationResult
  ├── Permission, Policy, PolicyBuilder
  └── Event/ (AuthenticationSucceeded, AuthenticationFailed, SessionCreated,
       SessionRefreshed, SessionInvalidated, AllSessionsInvalidated)
```

Each handler is an **invokable object** (`__invoke`) — independently testable, replaceable, composable. The orchestrators contain no business logic, only delegation.

### Test Structure

Tests mirror the `src/` directory:

```
tests/Integration/
├── GuardTest.php                          ← src/Guard.php
├── SessionManagerTest.php                 ← src/SessionManager.php
├── PasswordHasherTest.php                 ← src/PasswordHasher.php
├── PasswordAuthenticatorTest.php          ← src/PasswordAuthenticator.php
├── Data/
│   ├── AuthResultTest.php                 ← src/Data/AuthResult.php
│   ├── CredentialTest.php                 ← src/Data/Credential.php
│   ├── SubjectTest.php                    ← src/Data/Subject.php
│   ├── PermissionTest.php                 ← src/Data/Permission.php
│   ├── PolicyTest.php                     ← src/Data/Policy.php
│   ├── TokenTest.php                      ← src/Data/Token.php
│   └── HashedTokenTest.php                ← src/Data/HashedToken.php
├── Handler/Token/
│   └── VerifyTokenTest.php                ← src/Handler/Token/VerifyToken.php
└── Support/
    └── InMemoryTokenStoreTest.php         ← tests/Support/InMemoryTokenStore.php
```

---

## Contracts

Requires `jardissupport/contracts` ^2.8 and `jardissupport/dbquery` ^1.1. Defined in `jardissupport/contracts`:

| Interface | Purpose |
|-----------|---------|
| `TokenStoreInterface` | Token persistence: store, find, revoke, deleteExpired |
| `PasswordHasherInterface` | Hash, verify, needsRehash |
| `GuardInterface` | Permission check + authorize |
| `AuthenticatorInterface` | Authenticate credentials, return AuthResult |
| `TenantAwareAuthResultInterface` | AuthResult plus `getTenant()` (returned by `TokenAuthenticator`) |
| `RequestAttribute` | Request attribute names `SUBJECT` / `TENANT` for the authenticated session |

---

## Kernel Integration

Auth is wired directly — constructor injection, no framework hook. `DomainKernel` (the Koffer in `jardiscore/kernel`) exposes 11 accessors for cross-cutting infrastructure (cache, logger, database, HTTP client, mailer, filesystem, event dispatcher/registry), but no `auth()`: Auth is a support package you instantiate and wire yourself in your bounded context.

*(Earlier docs described this as "no service hook in `DomainApp`" — `DomainApp` was removed in the Kernel-Entkopplung refactor. The fact is unchanged, only the vocabulary: today's Koffer is `DomainKernel`, consumed by the generated `{Domain}Context`.)*

- **TokenStore**: `DbTokenStore` on the DomainKernel database connection, or implement `TokenStoreInterface` yourself (Redis, ...)
- **Policy**: Define as value object in application layer
- **Guard**: Instantiate in application layer, inject Policy

### ENV Variables (optional)

This package does not read the process environment itself — no `getenv`/`$_ENV`/DotEnv call exists in `src/`. The names below are a suggested convention for values you read yourself in the consuming application and pass explicitly into the constructors/methods (e.g. `AUTH_HASH_ALGO` → the `$algorithm` argument of `PasswordHasher`, `AUTH_TOKEN_LENGTH` → the length argument when generating a `Token`).

```env
# Password Hashing
AUTH_HASH_ALGO=argon2id
AUTH_HASH_MEMORY=65536
AUTH_HASH_TIME=4
AUTH_HASH_THREADS=1

# Token Defaults
AUTH_TOKEN_LENGTH=32
AUTH_ACCESS_TOKEN_TTL=3600
AUTH_REFRESH_TOKEN_TTL=604800
```

---

## What This Package Does NOT Do

- **No JWT** — opaque tokens only. JWT comes in v2 at the earliest
- **No OAuth2/OIDC** — no authorization server, no PKCE
- **No HTTP layer** — no cookies, no middleware, no `session_start()`
- **No user management** — no user model, no registration flow
- **No rate limiting** — brute-force protection is infrastructure concern
- **No other token persistence than SQL** — `DbTokenStore` covers MySQL/MariaDB, PostgreSQL, SQLite; anything else: implement `TokenStoreInterface`
- **No event dispatching** — events are returned to the caller, not dispatched internally

---

## Development

```bash
cp .env.example .env    # One-time setup
make install             # Install dependencies
make phpunit             # Run tests (starts a MariaDB 11.8 service, reachable inside the Compose network only)
make phpstan             # Static analysis (Level 8)
make phpcs               # Coding standards (PSR-12)
```

---

## Documentation

Full documentation, guides, and API reference:

**[docs.jardis.io/en/support/auth](https://docs.jardis.io/en/support/auth)**

---

## License

[MIT License](LICENSE.md) — free for any use, including commercial.

<!-- BEGIN jardis/dev-skills README block — do not edit by hand -->
## AI-Assisted Development

This package ships with a skill for Claude Code, Cursor, Continue, and Aider. Install it in your consuming project:

```bash
composer require --dev jardis/dev-skills
```

More details: <https://docs.jardis.io/en/skills>
<!-- END jardis/dev-skills README block -->
