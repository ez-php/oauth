<?php

declare(strict_types=1);

namespace EzPhp\OAuth;

use EzPhp\HttpClient\HttpClient;
use EzPhp\OAuth\Oidc\IdTokenValidator;

/**
 * Class OAuthClient
 *
 * OAuth2 authorization-code flow with mandatory PKCE (S256) and state
 * verification, against a single generically configured OAuthProvider.
 *
 * Fetching user info and mapping it onto an application user (e.g. via
 * ez-php/auth's UserProviderInterface) is deliberately left to the
 * application — see the module README for the recipe.
 *
 * @package EzPhp\OAuth
 */
final class OAuthClient
{
    private const int DEFAULT_STATE_TTL_SECONDS = 600;

    /**
     * Authorization-request parameters this client controls; see createAuthorizationUrl().
     *
     * @var list<string>
     */
    public const array RESERVED_PARAMS = [
        'response_type',
        'client_id',
        'redirect_uri',
        'state',
        'code_challenge',
        'code_challenge_method',
        'nonce',
    ];

    /**
     * OAuthClient Constructor
     *
     * @param OAuthProvider          $provider
     * @param HttpClient             $http
     * @param OAuthStateStoreInterface $stateStore
     * @param int                    $stateTtlSeconds How long a state/verifier pair remains redeemable.
     * @param IdTokenValidator|null  $idTokenValidator OpenID Connect: verifies the id_token of an `openid`
     *                                                  login in exchangeCode(); null leaves it unverified.
     */
    public function __construct(
        private readonly OAuthProvider $provider,
        private readonly HttpClient $http,
        private readonly OAuthStateStoreInterface $stateStore,
        private readonly int $stateTtlSeconds = self::DEFAULT_STATE_TTL_SECONDS,
        private readonly ?IdTokenValidator $idTokenValidator = null,
    ) {
    }

    /**
     * Build the authorization URL to redirect the user to, generating and
     * persisting a fresh state value and PKCE verifier — plus a `nonce` when the
     * effective scope contains `openid` (OpenID Connect).
     *
     * Neither `$extraParams` nor the provider's `authorizeParams` may set one of
     * RESERVED_PARAMS (response_type, client_id, redirect_uri, state,
     * code_challenge, code_challenge_method, nonce): overriding them would silently
     * defeat the state/PKCE/nonce protection, so it is rejected instead. Other keys
     * (including `scope`) are merged in, `$extraParams` winning over provider defaults.
     *
     * @param array<string, string> $extraParams Additional query parameters merged in, overriding provider defaults.
     *
     * @throws OAuthException When a reserved parameter would be overridden.
     *
     * @return string
     */
    public function createAuthorizationUrl(array $extraParams = []): string
    {
        $overridden = array_intersect(self::RESERVED_PARAMS, array_keys($this->provider->authorizeParams + $extraParams));

        if ($overridden !== []) {
            throw new OAuthException(
                'OAuth authorization parameters cannot override ' . implode(', ', $overridden)
                . ' — they carry the state/PKCE protection and the registered redirect.'
            );
        }

        $state = bin2hex(random_bytes(32));
        $verifier = Pkce::generateVerifier();

        $query = array_merge(
            [
                'response_type' => 'code',
                'client_id' => $this->provider->clientId,
                'redirect_uri' => $this->provider->redirectUri,
                'scope' => implode(' ', $this->provider->scopes),
                'state' => $state,
                'code_challenge' => Pkce::challengeFor($verifier),
                'code_challenge_method' => 'S256',
            ],
            $this->provider->authorizeParams,
            $extraParams,
        );

        $payload = ['verifier' => $verifier];

        // OpenID Connect: bind the ID token to this authorization request.
        if (in_array('openid', explode(' ', $query['scope']), true)) {
            $payload['nonce'] = $query['nonce'] = bin2hex(random_bytes(16));
        }

        $this->stateStore->put($state, $payload, $this->stateTtlSeconds);

        return $this->provider->authorizeUrl . '?' . http_build_query($query);
    }

    /**
     * Redeem an authorization code returned on the callback for an access token.
     *
     * For an OpenID Connect login (`openid` scope) with an IdTokenValidator, the
     * response's id_token is required and verified against the nonce stored with
     * the state; its claims are on the returned token (`idTokenClaims`).
     *
     * @param string $code
     * @param string $state
     *
     * @return OAuthToken
     * @throws OAuthException When the state is invalid/expired or the token endpoint rejects the exchange.
     */
    public function exchangeCode(string $code, string $state): OAuthToken
    {
        $payload = $this->stateStore->pull($state);

        if ($payload === null || !isset($payload['verifier']) || !is_string($payload['verifier'])) {
            throw new OAuthException('Invalid or expired OAuth state parameter.');
        }

        $token = $this->requestToken([
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->provider->redirectUri,
            'client_id' => $this->provider->clientId,
            'client_secret' => $this->provider->clientSecret,
            'code_verifier' => $payload['verifier'],
        ]);

        $nonce = $payload['nonce'] ?? null;

        if (!is_string($nonce) || $this->idTokenValidator === null) {
            return $token;
        }

        if ($token->idToken === null) {
            throw new OAuthException('Token endpoint response is missing the "id_token" of an OpenID Connect login.');
        }

        return $token->withIdTokenClaims($this->idTokenValidator->validate($token->idToken, $nonce));
    }

    /**
     * Exchange a refresh token for a new access token.
     *
     * @param string $refreshToken
     *
     * @return OAuthToken
     * @throws OAuthException When the token endpoint rejects the refresh.
     */
    public function refresh(string $refreshToken): OAuthToken
    {
        return $this->requestToken([
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
            'client_id' => $this->provider->clientId,
            'client_secret' => $this->provider->clientSecret,
        ]);
    }

    /**
     * @param array<string, string> $form
     *
     * @return OAuthToken
     * @throws OAuthException
     */
    private function requestToken(array $form): OAuthToken
    {
        $response = $this->http->post($this->provider->tokenUrl)->withForm($form)->send();

        if (!$response->ok()) {
            $body = $response->json();
            $error = is_array($body) && isset($body['error']) && is_string($body['error']) ? $body['error'] : null;

            throw new OAuthException(
                sprintf('Token endpoint returned status %d: %s', $response->status(), $response->body()),
                status: $response->status(),
                error: $error,
            );
        }

        $data = $response->json();

        if (!is_array($data)) {
            throw new OAuthException('Token endpoint response is not valid JSON.');
        }

        /** @var array<string, mixed> $data */
        return OAuthToken::fromArray($data);
    }
}
