<?php

declare(strict_types=1);

namespace EzPhp\OAuth;

/**
 * Interface OAuthStateStoreInterface
 *
 * Abstraction over the backing store used to persist the `state` value and
 * its associated PKCE verifier between the authorization redirect and the
 * callback request. Allows SessionOAuthStateStore to be swapped out in tests
 * or alternative session implementations.
 *
 * @package EzPhp\OAuth
 */
interface OAuthStateStoreInterface
{
    /**
     * Persist a payload under the given state, valid for $ttlSeconds.
     *
     * @param string               $state
     * @param array<string, mixed> $payload
     * @param int                  $ttlSeconds
     *
     * @return void
     */
    public function put(string $state, array $payload, int $ttlSeconds): void;

    /**
     * Retrieve and remove the payload for a state. One-time use: a state
     * must not be redeemable twice.
     *
     * @param string $state
     *
     * @return array<string, mixed>|null Null when the state is unknown or expired.
     */
    public function pull(string $state): ?array;
}
