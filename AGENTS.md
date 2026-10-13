# jardissupport/auth

Authentication, session management, password hashing, and RBAC — no HTTP layer, no JWT, no framework coupling. Six Orchestrators following the Closure-Orchestrator Pattern: `SessionManager`, `PasswordAuthenticator`, `TokenAuthenticator`, `DbTokenStore`, `PasswordHasher`, `Guard`.

## Usage essentials

- **Strict Orchestrator Pattern:** Six Orchestrators in `src/` root compose themselves from Closures (`src/Handler/{Category}/`) via `->__invoke(...)` binding in the constructor. Orchestrators have **zero business logic** — only delegation.
- **Events are plain readonly data objects** under `src/Data/Event/` (`AuthenticationSucceeded/Failed`, `SessionCreated/Refreshed/Invalidated`, `AllSessionsInvalidated`) — no interface, no Dispatcher. `SessionManager::create()/refresh()` return `SessionResult` with events; `invalidate()/invalidateAll()` return the event directly. The caller dispatches itself.
- **`DbTokenStore($connection, $table = 'auth_tokens')`** implements `TokenStoreInterface` via `jardissupport/dbquery` on a `DbConnectionInterface` (hash only; DDL per dialect in `resources/sql/{mysql,pgsql,sqlite}.sql`). **`TokenAuthenticator($store, $verifyToken, $tenantClaim = 'tenant', $expectedType = TokenType::Access)`** turns `Credential::token($plain)` into a `TenantAuthResult` (`TenantAwareAuthResultInterface`: subject + tenant from the access-token claim; reasons `Invalid token`/`Token expired`/`Token revoked`/`Unsupported credential type`). Attribute names for transports: `RequestAttribute::SUBJECT|TENANT` (contracts). The test fake `InMemoryTokenStore` lives in `tests/Support/`; tests run against MariaDB 11.8 (`make phpunit` starts it). `PasswordHasher::argon2id(memoryCost, timeCost, threads)` or `::bcrypt(cost)` as Factory Named Constructors.
- **`Guard` against immutable `Policy` via `PolicyBuilder`:** `role()->allow()->deny()->includes()->build()`. Rule semantics: **deny overrides allow**, role inheritance via `includes('editor')`. `check()` returns bool, `authorize()` throws `UnauthorizedException` (extends `RuntimeException`, **not** `AuthenticationException`).
- **Multi-role support:** `$session->getMetadata()['role']` may be `string` or `string[]` — `CheckPermission` iterates the list, **first match wins**. Permission format `"resource:action"` via `Permission::from()` with wildcard support.
- **Public error messages stay generic** (`"Invalid credentials"`), details are only in the events. `AuthenticationResult` implements `AuthResultInterface` — usable as both rich result and contract type. Exception hierarchy: `AuthenticationException` (base) → `InvalidCredential`/`TokenExpired`/`TokenRevoked`; `UnauthorizedException` separate.

## Full reference

https://docs.jardis.io/en/support/auth
