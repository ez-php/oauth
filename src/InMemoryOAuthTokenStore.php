<?php

declare(strict_types=1);

namespace EzPhp\OAuth;

/**
 * Class InMemoryOAuthTokenStore
 *
 * OAuthTokenStoreInterface for tests and single-process scripts: tokens live
 * as long as the instance.
 *
 * @package EzPhp\OAuth
 */
final class InMemoryOAuthTokenStore implements OAuthTokenStoreInterface
{
    /** @var array<string, OAuthToken> */
    private array $tokens = [];

    /**
     * @param string $key
     *
     * @return OAuthToken|null
     */
    public function get(string $key): ?OAuthToken
    {
        return $this->tokens[$key] ?? null;
    }

    /**
     * @param string     $key
     * @param OAuthToken $token
     *
     * @return void
     */
    public function put(string $key, OAuthToken $token): void
    {
        $this->tokens[$key] = $token;
    }

    /**
     * @param string $key
     *
     * @return void
     */
    public function forget(string $key): void
    {
        unset($this->tokens[$key]);
    }
}
