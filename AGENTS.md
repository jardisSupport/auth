# jardissupport/auth

Authentication, session management, password hashing, and RBAC — no HTTP layer, no JWT, no framework coupling. Four Orchestrators following the Closure-Orchestrator Pattern: `SessionManager`, `PasswordAuthenticator`, `PasswordHasher`, `Guard`.

## Usage essentials

- **Strict Orchestrator Pattern:** Four Orchestrators in `src/` root compose themselves from Closures (`src/Handler/{Category}/`) via `->__invoke(...)` binding in the constructor. Orchestrators have **zero business logic** — only delegation.
- **Events are plain readonly data objects** under `src/Data/Event/` (`AuthenticationSucceeded/Failed`, `SessionCreated/Refreshed/Invalidated`, `AllSessionsInvalidated`) — no interface, no Dispatcher. `SessionManager::create()/refresh()` return `SessionResult` with events; `invalidate()/invalidateAll()` return the event directly. The caller dispatches itself.
- **`TokenStoreInterface` must be implemented by the consumer** (from `jardissupport/contract`). No default store in the package — the test fake `InMemoryTokenStore` lives in `tests/Support/`, not in `src/`. `PasswordHasher::argon2id(memoryCost, timeCost, threads)` or `::bcrypt(cost)` as Factory Named Constructors.
- **`Guard` against immutable `Policy` via `PolicyBuilder`:** `role()->allow()->deny()->includes()->build()`. Rule semantics: **deny overrides allow**, role inheritance via `includes('editor')`. `check()` returns bool, `authorize()` throws `UnauthorizedException` (extends `RuntimeException`, **not** `AuthenticationException`).
- **Multi-role support:** `$session->getMetadata()['role']` may be `string` or `string[]` — `CheckPermission` iterates the list, **first match wins**. Permission format `"resource:action"` via `Permission::from()` with wildcard support.
- **Public error messages stay generic** (`"Invalid credentials"`), details are only in the events. `AuthenticationResult` implements `AuthResultInterface` — usable as both rich result and contract type. Exception hierarchy: `AuthenticationException` (base) → `InvalidCredential`/`TokenExpired`/`TokenRevoked`; `UnauthorizedException` separate.

## Full reference

https://docs.jardis.io/en/support/auth
