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

### Docking into `ez-php/auth`

This module stops at the token. Turning an `OAuthToken` into a logged-in
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
