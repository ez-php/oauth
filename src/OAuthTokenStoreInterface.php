<?php

declare(strict_types=1);

namespace EzPhp\OAuth;

/**
 * Interface OAuthTokenStoreInterface
 *
 * Persistent storage for issued tokens, keyed by an application-chosen string
 * (e.g. "spotify:42" — provider plus user). Used by OAuthTokenManager to load,
 * refresh and drop tokens.
 *
 * @package EzPhp\OAuth
 */
interface OAuthTokenStoreInterface
{
    /**
     * Return the stored token, or null when none is stored under the key.
     *
     * @param string $key
     *
     * @return OAuthToken|null
     */
    public function get(string $key): ?OAuthToken;

    /**
     * Store (insert or replace) the token under the key.
     *
     * @param string     $key
     * @param OAuthToken $token
     *
     * @return void
     */
    public function put(string $key, OAuthToken $token): void;

    /**
     * Delete the token stored under the key; a no-op when none is stored.
     *
     * @param string $key
     *
     * @return void
     */
    public function forget(string $key): void;
}
