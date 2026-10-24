# ez-php/oauth

OAuth2 authorization-code flow with mandatory PKCE (S256) and state
verification, against a generically configured provider — no built-in
catalog of specific providers (Google, GitHub, ...).

## Installation

```bash
composer require ez-php/oauth
```

Token exchange runs over `ez-php/http-client` (a hard dependency).

## Usage

Configure the provider once — its endpoints and credentials, not the flow itself:

```php
use EzPhp\OAuth\OAuthProvider;

$provider = new OAuthProvider(
    authorizeUrl: 'https://provider.example.com/oauth/authorize',
    tokenUrl: 'https://provider.example.com/oauth/token',
    clientId: getenv('OAUTH_CLIENT_ID'),
    clientSecret: getenv('OAUTH_CLIENT_SECRET'),
    redirectUri: 'https://app.example.com/oauth/callback',
    scopes: ['profile', 'email'],
);
```

Redirect the user to start the flow:

```php
use EzPhp\HttpClient\Http;
use EzPhp\OAuth\OAuthClient;
use EzPhp\OAuth\SessionOAuthStateStore;

$client = new OAuthClient($provider, Http::getClient(), new SessionOAuthStateStore());

header('Location: ' . $client->createAuthorizationUrl());
exit;
```

Extra authorization parameters (e.g. `prompt`, `login_hint`, or a narrower `scope`) go in
`createAuthorizationUrl(['prompt' => 'consent'])` or the provider's `authorizeParams`. The
parameters that carry the security of the flow — `response_type`, `client_id`, `redirect_uri`,
`state`, `code_challenge`, `code_challenge_method` (`OAuthClient::RESERVED_PARAMS`) — cannot be
overridden; trying to throws `OAuthException`.

Handle the callback:

```php
$token = $client->exchangeCode($_GET['code'], $_GET['state']);

// $token->accessToken, $token->refreshToken, $token->expiresIn, $token->scope
```

Refresh later:

```php
$token = $client->refresh($storedRefreshToken);
```

### Error handling

Every failure throws `OAuthException`. When the token endpoint answered with
a non-2xx status, `$e->status` holds that status and `$e->error` the RFC 6749
`error` code from the body (`null` if there was none); both are `null` for an
invalid state or a malformed success response:

```php
try {
    $token = $client->refresh($storedRefreshToken);
} catch (OAuthException $e) {
    if ($e->error === 'invalid_grant') {
        // refresh token revoked or expired — forget it, ask the user to log in again
    }

    throw $e; // 5xx / 429: provider trouble, keep the refresh token
}
```

### State storage

`SessionOAuthStateStore` persists the pending `state` value and PKCE verifier
in `$_SESSION` between the redirect and the callback request; start the
session before using it (e.g. a session-start middleware ahead of the OAuth
routes). Implement `OAuthStateStoreInterface` directly for another backing
store (e.g. a short-lived cache entry) if sessions aren't available.

### Stored tokens and automatic refresh

For API clients that call the provider on behalf of a user, store the token once and let
`OAuthTokenManager` handle expiry:

```php
use EzPhp\OAuth\OAuthTokenManager;
use EzPhp\OAuth\PdoOAuthTokenStore;

$store   = new PdoOAuthTokenStore($pdo);                        // creates `oauth_tokens` if needed
$manager = new OAuthTokenManager($client, $store, "spotify:{$userId}", leewaySeconds: 30);

$manager->store($client->exchangeCode($code, $state));          // after the callback

$response = $manager->send($http->get('https://api.spotify.com/v1/me'));
```

- The token is refreshed before a request when it expires within the leeway.
- A `401` triggers one refresh and one retry of the request.
- A refresh response without a `refresh_token` keeps the previous one.
- A rejected refresh (`400`/`401`, e.g. `invalid_grant`) deletes the stored token — the
  user has to authorize again; `5xx`/`429` and network errors keep it.

`authorize($request)` only adds the `Authorization: Bearer` header; `InMemoryOAuthTokenStore`
is the store for tests. Implement `OAuthTokenStoreInterface` for another backend.

#### Tokens at rest

`PdoOAuthTokenStore` (like `InMemoryOAuthTokenStore`) keeps the token **unencrypted**: the
`token` column holds the access and refresh token as plain JSON. A refresh token is a
long-lived credential, so either restrict access to the table like any other secret store,
or wrap the store in an encrypting decorator — `OAuthTokenStoreInterface` is three methods,
and the decorator works over any backend:

```php
use EzPhp\OAuth\OAuthException;
use EzPhp\OAuth\OAuthToken;
use EzPhp\OAuth\OAuthTokenStoreInterface;

final readonly class EncryptedOAuthTokenStore implements OAuthTokenStoreInterface
{
    /** @param string $key 32 random bytes (SODIUM_CRYPTO_SECRETBOX_KEYBYTES), kept outside the database */
    public function __construct(private OAuthTokenStoreInterface $inner, private string $key)
    {
    }

    public function get(string $key): ?OAuthToken
    {
        $token = $this->inner->get($key);

        return $token === null ? null : $this->map($token, $this->open(...));
    }

    public function put(string $key, OAuthToken $token): void
    {
        $this->inner->put($key, $this->map($token, $this->seal(...)));
    }

    public function forget(string $key): void
    {
        $this->inner->forget($key);
    }

    /** @param \Closure(string): string $codec */
    private function map(OAuthToken $t, \Closure $codec): OAuthToken
    {
        $refresh = $t->refreshToken === null ? null : $codec($t->refreshToken);

        return new OAuthToken($codec($t->accessToken), $t->tokenType, $t->expiresIn, $refresh, $t->scope, $t->issuedAt);
    }

    private function seal(string $plain): string
    {
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

        return base64_encode($nonce . sodium_crypto_secretbox($plain, $nonce, $this->key));
    }

    private function open(string $sealed): string
    {
        $raw = base64_decode($sealed, true);
        $nonce = substr((string) $raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $plain = sodium_crypto_secretbox_open(substr((string) $raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES), $nonce, $this->key);

        return $plain !== false ? $plain : throw new OAuthException('Stored OAuth token cannot be decrypted.');
    }
}

$store = new EncryptedOAuthTokenStore(new PdoOAuthTokenStore($pdo), $encryptionKey);
```

Needs `ext-sodium`. Rotating `$encryptionKey` makes existing rows undecryptable (the user
re-authorizes); the module ships no encrypting store itself, since key management is the
application's concern.

### OpenID Connect (SSO)

For an OpenID Provider (Google, Microsoft Entra ID, Keycloak, ...), read the endpoints from its
discovery document and give the client an `IdTokenValidator`. With `openid` in the scope,
`createAuthorizationUrl()` adds a `nonce`, and `exchangeCode()` requires the `id_token`, verifies it and
returns its claims — no separate user-info call needed:

```php
use EzPhp\OAuth\Oidc\IdTokenValidator;
use EzPhp\OAuth\Oidc\JwksProvider;
use EzPhp\OAuth\Oidc\ProviderMetadata;

$metadata = ProviderMetadata::discover($http, 'https://accounts.google.com'); // cache it: fromArray()
$provider = $metadata->toProvider($clientId, $clientSecret, 'https://app.example.com/oauth/callback', ['email', 'profile']);

$jwks = new JwksProvider($http, $metadata->jwksUri, $cache);     // $cache: optional ez-php/cache store
$validator = new IdTokenValidator($jwks, $metadata->issuer, $clientId);

$client = new OAuthClient($provider, $http, new SessionOAuthStateStore(), idTokenValidator: $validator);

// callback
$token = $client->exchangeCode($_GET['code'], $_GET['state']);
$userId = $token->idTokenClaims->subject;          // stable provider user ID
$email = $token->idTokenClaims->get('email');
```

What is checked: the signature (RS256 or ES256 only — `none`, HMAC and other algorithms are rejected),
with the JWKS key selected by `kid` and matching the algorithm's key type (an unknown `kid` refetches the
key set once, for key rotation); `iss` equals the discovered issuer; `aud` contains the client ID and `azp`
is the client ID when present or when there are several audiences; `exp`, `iat` and `nbf` with 60 s clock
leeway; a non-empty `sub`; and the `nonce` from the authorization request. Any failure throws
`OAuthException`. `discover()` also checks that the document's `issuer` is the one asked for.

Without a validator the raw `$token->idToken` is still returned, unverified — do not trust its contents.
The ID token is not part of `toStorage()`. Out of scope: OIDC logout/session management, implicit and
hybrid flows, encrypted (JWE) ID tokens, and a catalog of providers.

### Docking into `ez-php/auth`

This module stops at the token (or the verified ID token claims). Turning an `OAuthToken` into a logged-in
application user is application code: call the provider's user-info endpoint
with the access token, resolve or create a local user record, and hand it to
`EzPhp\Auth\Auth::login()` — commonly via an `ez-php/auth`
`UserProviderInterface` implementation that knows how to map the provider's
profile response onto your `UserInterface`. `ez-php/auth` itself is
unchanged; there is no dedicated docking class here because the profile
response shape is provider-specific.

## Development

```bash
composer install
composer full
```

## License

MIT
