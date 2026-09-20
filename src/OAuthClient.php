<?php

declare(strict_types=1);

namespace EzPhp\OAuth;

use EzPhp\HttpClient\HttpClient;

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
     * OAuthClient Constructor
     *
     * @param OAuthProvider          $provider
     * @param HttpClient             $http
     * @param OAuthStateStoreInterface $stateStore
     * @param int                    $stateTtlSeconds How long a state/verifier pair remains redeemable.
     */
    public function __construct(
        private readonly OAuthProvider $provider,
        private readonly HttpClient $http,
        private readonly OAuthStateStoreInterface $stateStore,
        private readonly int $stateTtlSeconds = self::DEFAULT_STATE_TTL_SECONDS,
    ) {
    }

    /**
     * Build the authorization URL to redirect the user to, generating and
     * persisting a fresh state value and PKCE verifier.
     *
     * @param array<string, string> $extraParams Additional query parameters merged in, overriding provider defaults.
     *
     * @return string
     */
    public function createAuthorizationUrl(array $extraParams = []): string
    {
        $state = bin2hex(random_bytes(32));
        $verifier = Pkce::generateVerifier();

        $this->stateStore->put($state, ['verifier' => $verifier], $this->stateTtlSeconds);

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

        return $this->provider->authorizeUrl . '?' . http_build_query($query);
    }

    /**
     * Redeem an authorization code returned on the callback for an access token.
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

        return $this->requestToken([
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->provider->redirectUri,
            'client_id' => $this->provider->clientId,
            'client_secret' => $this->provider->clientSecret,
            'code_verifier' => $payload['verifier'],
        ]);
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
            throw new OAuthException(sprintf(
                'Token endpoint returned status %d: %s',
                $response->status(),
                $response->body(),
            ));
        }

        $data = $response->json();

        if (!is_array($data)) {
            throw new OAuthException('Token endpoint response is not valid JSON.');
        }

        /** @var array<string, mixed> $data */
        return OAuthToken::fromArray($data);
    }
}
