# Jardis Auth

![Build Status](https://github.com/jardisSupport/auth/actions/workflows/ci.yml/badge.svg)
[![License: PolyForm Shield](https://img.shields.io/badge/License-PolyForm%20Shield-blue.svg)](LICENSE.md)
[![PHP Version](https://img.shields.io/badge/PHP-%3E%3D8.3-777BB4.svg)](https://www.php.net/)
[![PHPStan Level](https://img.shields.io/badge/PHPStan-Level%208-brightgreen.svg)](phpstan.neon)
[![PSR-12](https://img.shields.io/badge/Code%20Style-PSR--12-blue.svg)](phpcs.xml)

> Part of the **[Jardis Business Platform](https://jardis.io)** — Enterprise-grade PHP components for Domain-Driven Design

**Authentication and authorization without framework coupling.** Opaque tokens, session management, password hashing, and role-based access control — designed for DDD applications. No HTTP layer, no JWT, no external dependencies. Pure support package.

---

## Why This Package?

- **Four classes to learn** — `SessionManager`, `PasswordHasher`, `Guard`, `PasswordAuthenticator`. Everything else is data
- **Opaque tokens** — server-side state, SHA-256 hashed storage, no JWT complexity
- **Token rotation** — automatic refresh with old-token revocation
- **RBAC as Value Objects** — policies are immutable, defined in code, not in a database
- **Zero external dependencies** — uses PHP built-ins: `password_hash`, `random_bytes`, `hash_hmac`, `hash_equals`

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

The package defines `TokenStoreInterface` — you implement it in your infrastructure layer:

```php
use JardisSupport\Contract\Auth\TokenStoreInterface;
use JardisSupport\Auth\Data\HashedToken;

class DatabaseTokenStore implements TokenStoreInterface
{
    public function __construct(private PDO $pdo) {}

    public function store(HashedToken $token): void { /* INSERT */ }
    public function find(string $hash): ?HashedToken { /* SELECT */ }
    public function revoke(string $hash): void { /* UPDATE revoked = true */ }
    public function revokeAllForSubject(string $subject): void { /* UPDATE WHERE subject = ? */ }
    public function deleteExpired(): int { /* DELETE WHERE expires_at < NOW() */ }
}
```

An `InMemoryTokenStore` is included in `tests/Support/` for testing.

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

The user sees four orchestrators. Internally, each delegates to invokable handlers:

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

Defined in `jardissupport/contract` — implement these in your infrastructure:

| Interface | Purpose |
|-----------|---------|
| `TokenStoreInterface` | Token persistence: store, find, revoke, deleteExpired |
| `PasswordHasherInterface` | Hash, verify, needsRehash |
| `GuardInterface` | Permission check + authorize |
| `AuthenticatorInterface` | Authenticate credentials, return AuthResult |

---

## Foundation Integration

Auth is a **support package** — no service hook in `DomainApp`. Integration happens in your bounded context:

- **TokenStore**: Implement in infrastructure (database, Redis)
- **Policy**: Define as value object in application layer
- **Guard**: Instantiate in application layer, inject Policy

### ENV Variables (optional)

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
- **No token persistence** — only the interface. You implement the store
- **No event dispatching** — events are returned to the caller, not dispatched internally

---

## Development

```bash
cp .env.example .env    # One-time setup
make install             # Install dependencies
make phpunit             # Run tests
make phpstan             # Static analysis (Level 8)
make phpcs               # Coding standards (PSR-12)
```

---

## License

[PolyForm Shield License 1.0.0](LICENSE.md) — free for all use including commercial. Only restriction: don't build a competing framework.
