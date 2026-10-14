# Jardis Auth

![Build Status](https://github.com/jardisSupport/auth/actions/workflows/ci.yml/badge.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE.md)
[![PHP Version](https://img.shields.io/badge/PHP-%3E%3D8.3-777BB4.svg)](https://www.php.net/)
[![PHPStan Level](https://img.shields.io/badge/PHPStan-Level%208-brightgreen.svg)](phpstan.neon)
[![PSR-12](https://img.shields.io/badge/Code%20Style-PSR--12-blue.svg)](phpcs.xml)

> Part of **[Jardis](https://jardis.io)** — the Domain-Driven Design platform for PHP. You model your domain; Jardis generates the production-ready hexagonal code (DTOs, Command/Query handlers, repositories, persistence). This package is part of the open-source foundation that generated code runs on.

**Authentication and authorization without framework coupling.** A focused RBAC for PHP covering signed access tokens, opaque refresh tokens, session management, password hashing, and role-based access control — designed for DDD applications. No HTTP layer, no JWT, no third-party runtime dependencies beyond PHP built-ins and the Jardis packages `contracts` and `dbquery`. Pure support package.

---

## Why This Package?

- **Nine classes to learn** — `SessionManager`, `PasswordHasher`, `Guard`, `PasswordAuthenticator`, `SignedTokenAuthenticator`, `TokenAuthenticator`, `DbTokenStore`, `TokenIssuer`, `TokenRedeemer`. Everything else is data
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

$sessionManager = new SessionManager($tokenStore, $accessTokenKey); // 32-byte signing key, see "Session tokens"
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
use JardisSupport\Auth\Data\Credential;
use JardisSupport\Auth\SignedTokenAuthenticator;

// Verify an access token — signature + expiry, no store, no database
$result = (new SignedTokenAuthenticator($accessTokenKey))->authenticate(Credential::token($accessToken));

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

Instead of a closure, the third argument may be a `UserLookupInterface` (`jardissupport/contracts` >= 2.10, implemented by an account store such as `jardissupport/identity`). It returns a `CredentialRecordInterface` (`getPasswordHash()`, `getSubject()` as `type:id`, `getClaims()`) or `null`; a subject without `type:` becomes `user:<value>`. The claims are copied into the session at login (`SessionClaim::TENANT`, `SessionClaim::ROLE`).

```php
$authenticator = new PasswordAuthenticator($passwordHasher, $sessionManager, $accountStore); // UserLookupInterface
```

### Issue and redeem one-time tokens

Invitation, password-reset and verification links use `TokenIssuer` and `TokenRedeemer` on the same `TokenStoreInterface`. Only the hash is stored; the plain value is handed out once.

```php
use JardisSupport\Auth\TokenIssuer;
use JardisSupport\Auth\TokenRedeemer;
use JardisSupport\Contract\Auth\TokenType;

$issuer = new TokenIssuer($tokenStore);              // 2nd argument: token length in bytes (default 32)
$redeemer = new TokenRedeemer($tokenStore);          // 2nd argument: VerifyToken

$issued = $issuer->issue(TokenType::PasswordReset, Subject::from('42'), 3600, ['note' => 'x']);
$issued->plain;    // send this to the user, never store it
$issued->hashed;   // HashedToken as stored

$token = $redeemer->redeem($plainFromLink, TokenType::PasswordReset);  // HashedTokenInterface
$token->getSubject();   // 'user:42'
$token->getClaims();
```

`redeem()` revokes the token on success, so a second call throws `TokenRevokedException`. Unknown token or wrong type throws `InvalidCredentialException` (the token stays valid for its right type), an expired one `TokenExpiredException`.

### Invalidate Sessions

```php
// Single session (logout) — returns SessionInvalidated event
$event = $sessionManager->invalidate($session);

// All sessions for a subject (logout everywhere) — returns AllSessionsInvalidated event
$event = $sessionManager->invalidateAll('user:user-42');

// Exactly the session behind a session reference (see "Authenticate a Token") — other sessions
// of the same subject stay valid; idempotent, an unknown reference revokes nothing
$event = $sessionManager->invalidateByReference($result->getSessionReference());
```

**Revocation acts on the refresh token.** `invalidate()`, `invalidateByReference()` and `invalidateAll()` revoke refresh tokens in the store — `refresh($oldRefreshToken)` afterwards throws `AuthenticationException`. An already issued access token stays valid until its `exp` (default 15 minutes), see "Session tokens". `refresh()` rotates the refresh token and issues a new access token with a new session reference; the refreshed session keeps the claims of the original session. Claims with a `_` prefix are package-internal: they are never part of `Session::metadata` and never reach `TenantAuthResult`.

---

## Session tokens

> **Breaking since v1.5.0:** `SessionManager` takes the signing key as required second constructor argument (`new SessionManager($store, $accessTokenKey)`), and session access tokens are no longer stored. Authenticate them with `SignedTokenAuthenticator`, not `TokenAuthenticator`. Default access TTL is now 900 s (was 3600 s).

| Token | Form | Storage | Checked by |
|-------|------|---------|------------|
| Access | signed: `base64url(payload) . '.' . base64url(mac)` | none | `SignedTokenAuthenticator` — signature and `exp`, **no database access per request** |
| Refresh | opaque random value | SHA-256 hash in `TokenStoreInterface` | `SessionManager::refresh()` |

- **Signature:** `sodium_crypto_auth` (HMAC-SHA512-256) over the encoded payload; no header, no `alg` field, no JWT library. Payload: `{typ:"access", sub, sid, iat, exp, claims:{…}}`.
- **`sid`** (the session reference, `getSessionReference()`) is the hash of the session's refresh token: `invalidateByReference($sid)` revokes exactly that session's refresh.
- **Revocation happens at refresh:** an issued access token remains valid until `exp` (TTL default 900 s, refresh TTL 604800 s). Keep the access TTL short.
- **Key:** an own secret of exactly **32 bytes** — in `.env` as `AUTH_TOKEN_KEY` (base64), handed to the package as raw bytes: `base64_decode($_ENV['AUTH_TOKEN_KEY'], true)`. A key of another length throws `InvalidArgumentException`. Do not reuse `APP_SECRET_KEY`.
- **Rotation:** replacing the key invalidates **all** issued access tokens at once (clients refresh and get new ones signed with the new key); refresh tokens are unaffected.

---

## Token Store

`DbTokenStore` implements `TokenStoreInterface` on a `DbConnectionInterface` (`jardissupport/contracts`) using `jardissupport/dbquery` — no raw SQL, no own PDO. Only the SHA-256 hash of a token is stored, never the plain value.

```php
use JardisSupport\Auth\DbTokenStore;

$store = new DbTokenStore($connection);                 // table: auth_tokens
$store = new DbTokenStore($connection, 'my_tokens');    // custom table name (plain identifier)

$sessionManager = new SessionManager($store, $accessTokenKey);
```

The store holds refresh tokens and one-time tokens (API keys, verification, password reset); session access tokens are signed and never stored.

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

**Session access tokens** (issued by `SessionManager`) are authenticated by `SignedTokenAuthenticator($accessTokenKey, $tenantClaim = SessionClaim::TENANT)`: same result type, same reasons (`Invalid token`, `Token expired`, `Unsupported credential type`; never `Token revoked` — revocation acts at refresh), no store. `getSessionReference()` is the token's `sid`.

`TokenAuthenticator` resolves a **stored** token (API key, verification, password reset, or any `TokenIssuer`-issued token; `$expectedType` selects the type): a valid, non-revoked, non-expired token yields a successful `SessionAwareAuthResultInterface` with qualified subject, bare subject id, tenant **and** a session reference; any other token yields a failure with a reason.

```php
use JardisSupport\Auth\Data\Credential;
use JardisSupport\Auth\TokenAuthenticator;
use JardisSupport\Contract\Auth\RequestAttribute;

// The tenant is a claim of the token, set when the session / token is created:
$session = $sessionManager->create(Subject::from('42'), ['tenant' => 'acme']);

$authenticator = new TokenAuthenticator($store);               // tenant claim: 'tenant'
$authenticator = new TokenAuthenticator($store, tenantClaim: 'org');

$result = $authenticator->authenticate(Credential::token($bearerToken));

if ($result->isSuccess()) {
    $request = $request
        ->withAttribute(RequestAttribute::SUBJECT, $result->getSubject())           // 'user:42'
        ->withAttribute(RequestAttribute::SUBJECT_ID, $result->getSubjectId())       // '42'
        ->withAttribute(RequestAttribute::TENANT, $result->getTenant())              // 'acme' | null
        ->withAttribute(RequestAttribute::SESSION, $result->getSessionReference());  // hash of the access token
} else {
    $result->getReason(); // 'Invalid token' | 'Token expired' | 'Token revoked' | 'Unsupported credential type'
}
```

Only `TokenType::Access` tokens are accepted by default (4th constructor argument changes that). The attribute names `RequestAttribute::SUBJECT` (`jardisSubject`) and `RequestAttribute::TENANT` (`jardisTenant`) live in `jardissupport/contracts` (>= 2.8.0); `SUBJECT_ID`, `SESSION` and `SessionAwareAuthResultInterface` since 2.9.0.

The **session reference** of a stored-token result is the SHA-256 hash of the presented token; for a signed access token it is the `sid` (hash of the refresh token); `SessionManager::invalidateByReference()` revokes exactly that session's refresh token. Any other place that needs the hash of a plain token uses the one function `HashedToken::hashOf(string $plainToken): string` — never `hash('sha256', …)` in the consumer. `Subject::parse('user:42')` is the inverse of `Subject::toString()`.

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

The user sees nine orchestrators. Internally, each delegates to invokable handlers:

```
SessionManager (Orchestrator)
  ├── Handler/Session/CreateSession         store refresh token, sign access token (sid = refresh hash) + SessionCreated event
  ├── Handler/Session/RefreshSession        rotate tokens + SessionRefreshed event
  ├── Handler/Session/InvalidateSession     revoke single session + SessionInvalidated event
  ├── Handler/Session/InvalidateSessionByReference revoke the session's refresh token (sid)
  ├── Handler/Token/SignAccessToken         payload → signed access token
  ├── Handler/Token/VerifyAccessToken       signed access token → payload (MAC, typ, exp) or null
  └── Handler/Session/InvalidateAllSessions revoke all + AllSessionsInvalidated event

PasswordAuthenticator (Orchestrator)
  ├── Handler/Authentication/LookupUser      resolve user via $userLookup closure
  ├── Handler/Authentication/LookupCredentialRecord resolve user via UserLookupInterface
  ├── Handler/Authentication/VerifyCredential verify password against hash
  └── Handler/Authentication/BuildAuthResult  assemble AuthenticationResult + events

SignedTokenAuthenticator (Orchestrator)
  └── Handler/Authentication/AuthenticateSignedToken  verify signature + exp → subject + tenant claim + sid → TenantAuthResult

TokenAuthenticator (Orchestrator)
  └── Handler/Authentication/AuthenticateToken  lookup → verify → subject + subject id + tenant claim + session reference → TenantAuthResult

TokenIssuer (Orchestrator)
  └── Handler/Token/IssueToken              create token, store hash → IssuedToken

TokenRedeemer (Orchestrator)
  └── Handler/Token/RedeemToken             find → verify (type, expiry, revocation) → revoke → stored token

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
  ├── Token, HashedToken, IssuedToken, TokenType
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
├── TokenIssuerTest.php                    ← src/TokenIssuer.php
├── TokenRedeemerTest.php                  ← src/TokenRedeemer.php
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

Requires `jardissupport/contracts` ^2.10 and `jardissupport/dbquery` ^1.1. Defined in `jardissupport/contracts`:

| Interface | Purpose |
|-----------|---------|
| `TokenStoreInterface` | Token persistence: store, find, revoke, deleteExpired |
| `PasswordHasherInterface` | Hash, verify, needsRehash |
| `GuardInterface` | Permission check + authorize |
| `AuthenticatorInterface` | Authenticate credentials, return AuthResult |
| `TenantAwareAuthResultInterface` | AuthResult plus `getTenant()` |
| `SessionAwareAuthResultInterface` | TenantAware plus `getSubjectId()` and `getSessionReference()` (returned by `SignedTokenAuthenticator` and `TokenAuthenticator`) |
| `UserLookupInterface` | `lookup(string $identifier): ?CredentialRecordInterface` — login lookup port, accepted by `PasswordAuthenticator` |
| `CredentialRecordInterface` | `getPasswordHash()`, `getSubject()` (`type:id`), `getClaims()` |
| `SessionClaim` | Claim names `TENANT` / `ROLE` (default of `TokenAuthenticator`, key read by `Guard`) |
| `RequestAttribute` | Request attribute names `SUBJECT` / `SUBJECT_ID` / `TENANT` / `SESSION` for the authenticated session |

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
AUTH_ACCESS_TOKEN_TTL=900
# 32 bytes, base64 (e.g. `openssl rand -base64 32`); decode before handing to SessionManager
AUTH_TOKEN_KEY=
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
