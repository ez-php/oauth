<?php

declare(strict_types=1);

namespace EzPhp\OAuth;

use Closure;
use EzPhp\HttpClient\HttpClientException;
use EzPhp\HttpClient\HttpRequest;
use EzPhp\HttpClient\HttpResponse;

/**
 * Class OAuthTokenManager
 *
 * Bearer requests against an OAuth-protected API with a stored token that is
 * refreshed on demand — what every API client otherwise hand-rolls:
 *
 * - token() loads the stored token and refreshes it when it is expired, or
 *   expires within `$leewaySeconds` (clock skew, slow requests).
 * - send() adds `Authorization: Bearer …`, and on a 401 refreshes once and
 *   retries the request once.
 * - A refresh response without a refresh token keeps the previous one
 *   (providers may or may not rotate it).
 * - A refresh the provider *rejects* (400/401, e.g. `invalid_grant`) deletes
 *   the stored token — it can never work again, the user has to re-authorize.
 *   A 5xx/429 answer or a network error keeps it, so a provider outage does
 *   not log everyone out.
 *
 * One manager per stored token (`$key`, e.g. "spotify:42"). The refresh is
 * not locked against concurrent processes; providers that invalidate a
 * refresh token on use need that serialisation at the application level.
 *
 * @package EzPhp\OAuth
 */
final readonly class OAuthTokenManager
{
    /**
     * @param OAuthClient                 $client        Performs the refresh grant.
     * @param OAuthTokenStoreInterface    $store         Where the token is kept.
     * @param string                      $key           Store key of this token.
     * @param int                         $leewaySeconds Refresh this many seconds before the expiry.
     * @param (Closure(): int)|null       $clock         Current Unix time; null = time().
     */
    public function __construct(
        private OAuthClient $client,
        private OAuthTokenStoreInterface $store,
        private string $key,
        private int $leewaySeconds = 30,
        private ?Closure $clock = null,
    ) {
    }

    /**
     * Store a freshly issued token (e.g. the result of OAuthClient::exchangeCode()).
     *
     * @param OAuthToken $token
     *
     * @return void
     */
    public function store(OAuthToken $token): void
    {
        $this->store->put($this->key, $token);
    }

    /**
     * Whether a token is stored under this manager's key.
     *
     * @return bool
     */
    public function hasToken(): bool
    {
        return $this->store->get($this->key) !== null;
    }

    /**
     * Return a usable token, refreshing it first when it is (about to be) expired.
     *
     * @return OAuthToken
     * @throws OAuthException When no token is stored or the refresh fails.
     * @throws HttpClientException When the refresh request fails on the transport.
     */
    public function token(): OAuthToken
    {
        $token = $this->stored();

        if ($token->isExpired($this->leewaySeconds, $this->now())) {
            return $this->refresh($token);
        }

        return $token;
    }

    /**
     * Return the request with the current token as `Authorization: Bearer` header.
     *
     * @param HttpRequest $request
     *
     * @return HttpRequest
     * @throws OAuthException When no token is stored or the refresh fails.
     */
    public function authorize(HttpRequest $request): HttpRequest
    {
        return self::withBearer($request, $this->token());
    }

    /**
     * Send the request with the current token; on a 401 refresh once and retry once.
     *
     * The second response is returned as it is, even when it is a 401 again.
     *
     * @param HttpRequest $request
     *
     * @return HttpResponse
     * @throws OAuthException When no token is stored or a refresh fails.
     * @throws HttpClientException On transport errors.
     */
    public function send(HttpRequest $request): HttpResponse
    {
        $token = $this->token();
        $response = self::withBearer($request, $token)->send();

        if ($response->status() !== 401) {
            return $response;
        }

        return self::withBearer($request, $this->refresh($token))->send();
    }

    /**
     * Run the refresh grant, keep the old refresh token when none comes back,
     * store the result — or drop the stored token when the grant is rejected.
     *
     * @param OAuthToken $token
     *
     * @return OAuthToken
     * @throws OAuthException
     * @throws HttpClientException
     */
    private function refresh(OAuthToken $token): OAuthToken
    {
        if ($token->refreshToken === null || $token->refreshToken === '') {
            throw new OAuthException("OAuth token '{$this->key}' expired and has no refresh token; re-authorization is required.");
        }

        try {
            $fresh = $this->client->refresh($token->refreshToken);
        } catch (OAuthException $e) {
            if ($e->status === 400 || $e->status === 401) {
                $this->store->forget($this->key);
            }

            throw $e;
        }

        if ($fresh->refreshToken === null) {
            $fresh = $fresh->withRefreshToken($token->refreshToken);
        }

        $fresh = $fresh->withIssuedAt($this->now());
        $this->store->put($this->key, $fresh);

        return $fresh;
    }

    /**
     * @return OAuthToken
     * @throws OAuthException
     */
    private function stored(): OAuthToken
    {
        return $this->store->get($this->key)
            ?? throw new OAuthException("No OAuth token stored under '{$this->key}'; authorize first.");
    }

    /**
     * @return int
     */
    private function now(): int
    {
        return $this->clock !== null ? ($this->clock)() : time();
    }

    /**
     * @param HttpRequest $request
     * @param OAuthToken  $token
     *
     * @return HttpRequest
     */
    private static function withBearer(HttpRequest $request, OAuthToken $token): HttpRequest
    {
        return $request->withHeader('Authorization', 'Bearer ' . $token->accessToken);
    }
}
