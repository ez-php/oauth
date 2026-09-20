# Coding Guidelines

Applies to the entire ez-php project — framework core, all modules, and the application template.

---

## Environment

- PHP **8.5**, Composer for dependency management
- All project based commands run **inside Docker** — never directly on the host

```
docker compose exec app <command>
```

Container name: `ez-php-app`, service name: `app`.

---

## Quality Suite

Run after every change:

```
docker compose exec app composer full
```

Executes in order:
1. `sync_guidelines.php --check` — fails if any `CLAUDE.md` has drifted from this file
2. `check_test_classes.php` — fails on a duplicate test class name (all packages share the `Tests\` namespace, so a collision is a fatal error in the aggregated run, not a test failure)
3. `phpstan analyse` — static analysis, level 9, config: `phpstan.neon`
4. `php-cs-fixer fix` — auto-fixes style (`@PSR12` + `@PHP83Migration` + strict rules)
   *(Note: `@PHP85Migration` does not exist yet in php-cs-fixer; `@PHP83Migration` is the highest available and is used intentionally even though the project targets PHP 8.5)*
5. `phpunit` — all tests with coverage

Individual commands when needed:
```
composer analyse             # PHPStan only
composer cs                  # CS Fixer only
composer test                # PHPUnit only
composer guidelines:check    # CLAUDE.md drift only
composer test-classes:check  # duplicate test class names only
```

**PHPStan:** never suppress with `@phpstan-ignore-line` — always fix the root cause.

---

## Coding Standards

- `declare(strict_types=1)` at the top of every PHP file
- Typed properties, parameters, and return values — avoid `mixed`
- PHPDoc on every class and public method
- One responsibility per class — keep classes small and focused
- Constructor injection — no service locator pattern
- No global state unless intentional and documented
- Concrete classes are `final` — extend behavior through composition, not inheritance. Exception-hierarchy base classes (e.g. `EzPhpException`, `HttpException`, `CacheException`) are one carve-out, since they exist specifically to be extended. A documented template-method-style base class (e.g. `Mailable`, meant to be configured via constructor-time subclassing) is the other — the owning module's `CLAUDE.md` must record it under Design Decisions.

**Naming:**

| Thing | Convention |
|---|---|
| Classes / Interfaces | `PascalCase` |
| Methods / variables | `camelCase` |
| Constants | `UPPER_CASE` |
| Files | Match class name exactly |

**Principles:** SOLID · KISS · DRY · YAGNI

---

## Workflow & Behavior

- Write tests **before or alongside** production code (test-first)
- Read and understand the relevant code before making any changes
- Modify the minimal number of files necessary
- Keep implementations small — if it feels big, it likely belongs in a separate module
- No hidden magic — everything must be explicit and traceable
- No large abstractions without clear necessity
- No heavy dependencies — check if PHP stdlib suffices first
- Respect module boundaries — don't reach across packages
- Keep the framework core small — what belongs in a module stays there
- Document architectural reasoning for non-obvious design decisions
- Do not change public APIs unless necessary
- Prefer composition over inheritance — no premature abstractions

---

## New Modules & CLAUDE.md Files

### 1 — Required files

Every module under `modules/<name>/` must have:

| File | Purpose |
|---|---|
| `composer.json` | package definition, deps, autoload |
| `phpstan.neon` | static analysis config, level 9 |
| `phpunit.xml` | test suite config |
| `.php-cs-fixer.php` | code style config |
| `.gitignore` | ignore `vendor/`, `.env`, cache |
| `.env.example` | environment variable defaults (copy to `.env` on first run) |
| `docker-compose.yml` | Docker Compose service definition (always `container_name: ez-php-<name>-app`) |
| `docker/app/Dockerfile` | module Docker image (`FROM au9500/php:8.5`) |
| `docker/app/container-start.sh` | container entrypoint: `composer install` → `sleep infinity` |
| `docker/app/php.ini` | PHP ini overrides (`memory_limit`, `display_errors`, `xdebug.mode`) |
| `.github/workflows/ci.yml` | standalone CI pipeline |
| `README.md` | public documentation |
| `tests/TestCase.php` | base test case for the module |
| `start.sh` | convenience script: copy `.env`, bring up Docker, wait for services, exec shell |
| `CLAUDE.md` | see section 2 below |

### 2 — CLAUDE.md structure

Every module `CLAUDE.md` must follow this exact structure:

1. **Full content of `CODING_GUIDELINES.md`, verbatim** — copy it as-is, do not summarize or shorten
2. A `---` separator
3. `# Package: ez-php/<name>` (or `# Directory: <name>` for non-package directories)
4. Module-specific section covering:
   - Source structure — file tree with one-line description per file
   - Key classes and their responsibilities
   - Design decisions and constraints
   - Testing approach and infrastructure requirements (MySQL, Redis, etc.)
   - What does **not** belong in this module

**Do not edit part 1 by hand.** It is generated from `CODING_GUIDELINES.md` by
`sync_guidelines.php` at the project root:

```
php sync_guidelines.php            # rewrite every out-of-sync CLAUDE.md
php sync_guidelines.php --check    # report drift, exit 1 if any (CI / pre-commit)
```

Edit `CODING_GUIDELINES.md`, then run the script — it replaces everything before the
`# Package:` / `# Directory:` / `# Project:` heading and preserves the hand-written
section below it byte-for-byte. Editing a single copy only creates drift; before this
script existed, all 40 copies had diverged.

### 3 — Scaffolding a new module

`make_module.php` at the project root writes the required-file set and the monorepo
wiring in one step, wrapping `docker-init` for the Docker subset:

```
composer module:make <name> -- --description="..."
php make_module.php <name> --description="..." --services=mysql,redis
```

`<name>` is the kebab-case package name; the namespace is derived as
`EzPhp\<PascalCase>` unless `--namespace=` overrides it (`bignum` → `BigNum`,
`opcache` → `OPCache`, and `dotenv` → `Env` are existing exceptions the guess
gets wrong).

To bring in a module whose code already lives in its own repository instead of
generating a fresh skeleton, pass `--repo=` with a git URL:

```
php make_module.php <name> --repo=<git-url> [--namespace=Foo]
```

This runs `git submodule add <url> modules/<name>` instead of writing package
files, then applies the same monorepo wiring below. It is mutually exclusive
with `--services` and `--description` — a submodule brings its own Docker
scaffold (if any) and its own `composer.json` description. A minimal `CLAUDE.md`
stub is written only if the submodule doesn't already ship one, so
`composer guidelines:sync` has a `# Package:` heading to anchor part 1 against.

It writes `modules/<name>/` and registers the module in the four places the monorepo
needs it — root `composer.json` (`autoload.psr-4`), `phpstan.neon`, `phpunit.xml`
(test suite **and** coverage source), and `packages.sh` (alphabetical position).

Two things stay manual on purpose:

- **`CLAUDE.md` part 1** — only the `# Package:` section is generated. Run
  `composer guidelines:sync` afterwards; baking a guidelines copy into the generator
  would recreate the drift the sync script exists to prevent.
- **The host-port table below** (`--services` only) — editing it marks all ~40
  `CLAUDE.md` copies as drifted at once, so the next `composer full` would fail for
  a brand-new module. The generator prints which ports to claim instead.

### 4 — Docker scaffold

Run from the new module root (requires `"ez-php/docker": "^2.0"` in `require-dev`):

```
vendor/bin/docker-init
```

This copies `Dockerfile`, `docker-compose.yml`, `.env.example`, `start.sh`, and `docker/` into the module, replacing `{{MODULE_NAME}}` placeholders. Existing files are never overwritten.

Pass `--services` to merge MySQL/Redis/Meilisearch service definitions directly into `docker-compose.yml` and uncomment the matching sections in `.env.example`, instead of adapting them by hand afterward:

```
vendor/bin/docker-init --services=mysql
vendor/bin/docker-init --services=redis
vendor/bin/docker-init --services=meilisearch
vendor/bin/docker-init --services=mysql,redis
```

Pass `--extensions` to merge PHP extension install blocks (apt packages plus `docker-php-ext-install`/`pecl` lines) directly into `docker/app/Dockerfile`, instead of hand-editing it afterward — supported extensions: `bcmath`, `gmp`, `gd`, `imagick`:

```
vendor/bin/docker-init --extensions=gmp,bcmath
vendor/bin/docker-init --extensions=gd,imagick
```

When run from a module directory inside this monorepo, any requested extension not already present is also merged into the shared root `docker/app/Dockerfile` — the container `composer full` at the root actually runs against, distinct from the module's own standalone image.

After scaffolding:

1. Adapt `docker-compose.yml` — add or remove services (MySQL, Redis, Meilisearch) as needed
2. Adapt `.env.example` — fill in connection defaults matching the services above
3. Assign a unique host port for each exposed service (see table below)

**Allocated host ports:**

| Package | `DB_HOST_PORT` (MySQL) | Redis host port | `MEILISEARCH_PORT` |
|---|---|---|---|
| root (`ez-php-project`) | 3306 | 6379 (`REDIS_PORT`) | 7700 |
| `ez-php/framework` | 3307 | — | — |
| `ez-php/` (application template) | 3308 | 6383 (`REDIS_PORT`) | — |
| `ez-php/orm` | 3309 | — | — |
| `ez-php/cache` | — | 6380 (`REDIS_HOST_PORT`) | — |
| `ez-php/queue` | 3310 | 6381 (`REDIS_HOST_PORT`) | — |
| `ez-php/rate-limiter` | — | 6382 (`REDIS_HOST_PORT`) | — |
| `ez-php/search` | — | — | 7701 |
| `ez-php/event-store` | 3311 | — | — |
| **next free** | **3312** | **6384** | **7702** |

Only set a port for services the module actually uses. Modules without external services need no port config.

> The `MEILISEARCH_PORT` column is the **host** port. Inside a Compose network the service is always reachable at `http://meilisearch:7700` regardless of the host mapping — only publish-side ports need to be unique.

> The "Redis host port" column is likewise the **host**-published port. `ez-php/cache`, `ez-php/queue`, and `ez-php/rate-limiter` map it through a separate `REDIS_HOST_PORT` env var in `docker-compose.yml`, keeping `REDIS_PORT` fixed at `6379` for in-container connections (the app container always reaches Redis at `redis:6379` over the Compose network, regardless of the host mapping) — the root project and the `ez-php/` application template are the two exceptions, since both have no host/container split and use `REDIS_PORT` for both (the template's other in-container Redis settings — `CACHE_REDIS_PORT`, `QUEUE_REDIS_PORT`, `RATE_LIMITER_REDIS_PORT` — stay fixed at `6379` regardless, same as every other module).

> This table tracks only MySQL, Redis, and Meilisearch ports — the three services shared across multiple modules where a collision is otherwise easy to introduce. `ez-php/mail`'s Mailpit service is the one other module with published host ports: SMTP `1025` and web UI `8025`, mapped through `MAILPIT_SMTP_HOST_PORT`/`MAILPIT_API_HOST_PORT` in `modules/mail/docker-compose.yml` (mirroring the `*_HOST_PORT` pattern above), documented in `modules/mail/.env.example`. It isn't a table column because no other module runs Mailpit, so there is nothing to collide with — but a new module adding its own single-use service's ports should likewise parameterize them and document the defaults in its own `.env.example` rather than adding a column here.

### 5 — Monorepo scripts

`packages.sh` at the project root is the **central package registry**. Both `push_all.sh` and `update_all.sh` source it — the package list lives in exactly one place.

When adding a new module, add `"$ROOT/modules/<name>"` to the `PACKAGES` array in `packages.sh` in **alphabetical order** among the other `modules/*` entries (before `framework`, `ez-php`, and the root entry at the end).

---

# Package: ez-php/oauth

> This file is the module-specific half. The coding guidelines above it are
> generated by `sync_guidelines.php` — run `composer guidelines:sync` from the
> monorepo root to fill them in. Never edit that part by hand.

---

## Source Structure

```
src/
  OAuthProvider.php          — immutable config for one authorization server (endpoints, credentials, scopes)
  OAuthToken.php              — immutable token endpoint response (access/refresh token, expiry, scope)
  OAuthStateStoreInterface.php — backing store for the pending state/PKCE-verifier pair between redirect and callback
  SessionOAuthStateStore.php  — $_SESSION-backed OAuthStateStoreInterface implementation
  Pkce.php                     — RFC 7636 code verifier/challenge generation (S256 only)
  OAuthException.php           — thrown on invalid/expired state or a token endpoint error
  OAuthClient.php               — the flow: createAuthorizationUrl(), exchangeCode(), refresh()
tests/
  TestCase.php                 — base test case
  PkceTest.php                  — verifier format, RFC 7636 test vector, determinism
  OAuthTokenTest.php            — fromArray() parsing/defaults/validation, isExpired()
  SessionOAuthStateStoreTest.php — put/pull, one-time use, expiry, inactive-session guard
  OAuthClientTest.php           — authorization URL shape, PKCE/state round-trip via FakeTransport, refresh, error paths
```

---

## Key Classes and Responsibilities

**`OAuthClient`** — the whole flow, against one `OAuthProvider`:

| Method | Behaviour |
|---|---|
| `createAuthorizationUrl(array $extraParams = [])` | Generates state + PKCE verifier, persists them via `OAuthStateStoreInterface`, returns the full authorize-endpoint URL (`response_type=code`, `code_challenge_method=S256`, ...) |
| `exchangeCode(string $code, string $state)` | Redeems the state (one-time use) for its verifier, POSTs `grant_type=authorization_code` + `code_verifier` to the token endpoint via `ez-php/http-client`, returns an `OAuthToken` |
| `refresh(string $refreshToken)` | POSTs `grant_type=refresh_token` to the token endpoint, returns a new `OAuthToken` |

**`OAuthProvider`** — pure config value object: `authorizeUrl`, `tokenUrl`, `clientId`, `clientSecret`, `redirectUri`, `scopes`, `authorizeParams`. No built-in catalog of specific providers — the application supplies its own.

**`OAuthToken`** — value object for the token endpoint response. `OAuthToken::fromArray()` parses the decoded JSON, defaulting `token_type` to `bearer` and throwing `OAuthException` if `access_token` is missing/empty. `isExpired()` compares `issuedAt + expiresIn` against the current time, always `false` when the provider omitted `expires_in`.

**`Pkce`** — static-only helper: `generateVerifier()` (64 random bytes, base64url) and `challengeFor($verifier)` (S256/base64url). No `plain` transform — S256 is the only method offered.

**`OAuthStateStoreInterface`** / **`SessionOAuthStateStore`** — `put()`/`pull()` persist the state → verifier mapping between the two requests of the flow. `pull()` is one-time use (state cannot be redeemed twice) and expiry-checked. Mirrors `framework`'s `CsrfTokenStoreInterface`/`SessionCsrfTokenStore` pattern; the session must already be started by the application.

---

## Design Decisions and Constraints

- **PKCE (S256) and `state` are mandatory, not optional.** There is no code path that skips either — every authorization URL includes a `code_challenge`, and `exchangeCode()` always requires a verifier recovered from the state store. This is a security-critical flow (TODO.md's own assessment); making PKCE opt-in would let an application accidentally ship the weaker plain authorization-code flow.
- **No provider catalog.** `OAuthProvider` is a generic config object; there are no `GoogleProvider`/`GitHubProvider` subclasses. Per-provider quirks (non-standard token response fields, extra authorize params) are handled via `OAuthProvider::$authorizeParams` and `OAuthToken::fromArray()`'s tolerant parsing, not per-provider classes.
- **No user-info fetching or `ez-php/auth` docking class.** The module stops at `OAuthToken`. Calling the provider's user-info endpoint and mapping the response onto an application `UserInterface` is application code — the shape of that response is entirely provider-specific, so any generic abstraction here would be speculative. `ez-php/auth` is not modified; applications typically implement `UserProviderInterface` themselves once they have the profile data. See README.md "Docking into ez-php/auth".
- **No service provider.** Unlike `AuthServiceProvider`/`JwtServiceProvider`, there is no `OAuthServiceProvider` — an application may need multiple `OAuthClient` instances (one per provider: Google, GitHub, ...) with different credentials, so a single container binding would not generalize. Applications construct `OAuthClient` directly, same as `IdempotencyMiddleware`.
- **Token exchange goes through `ez-php/http-client`'s `TransportInterface` seam** (a hard `require`, not a soft dependency like `ez-php/idempotency`'s cache) — `HttpClient` is constructed by the application and injected, so tests substitute `FakeTransport` and never hit the network.
- **State store is a hard interface dependency, `SessionOAuthStateStore` the only bundled implementation.** Applications without PHP sessions (e.g. a stateless API gateway) implement `OAuthStateStoreInterface` against their own short-lived store (cache, signed cookie, ...).

---

## Testing Approach

- No external services: state storage tests use real PHP sessions (`session_start()`/`session_write_close()` in `setUp()`/`tearDown()`, same approach as `ez-php/auth`'s session tests); HTTP tests use `ez-php/http-client`'s `FakeTransport` — no real network calls, no Docker services beyond the app container.
- `PkceTest` includes the RFC 7636 Appendix B test vector to pin the S256 derivation exactly, not just structurally.
- Test classes live in the shared `Tests\` namespace but must be uniquely named
  across the whole monorepo — the root `phpunit.xml` loads every package in one
  process, so a duplicate name is a fatal error, not a test failure. Prefix with
  `OAuth` when the obvious name is already taken.

---

## What Does NOT Belong Here

| Concern | Where it belongs |
|---|---|
| Specific provider catalogs (Google, GitHub, ...) | Application code configuring `OAuthProvider` |
| Fetching user info / mapping to an application user | Application code, typically an `ez-php/auth` `UserProviderInterface` implementation |
| Session lifecycle (start/destroy) | Application session middleware |
| Password-based / Bearer-token authentication | `ez-php/auth` |
| HTTP transport, retries, streaming | `ez-php/http-client` |
| Request/response value objects | `ez-php/http` |