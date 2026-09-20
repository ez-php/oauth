<?php

declare(strict_types=1);

namespace EzPhp\OAuth;

/**
 * Class SessionOAuthStateStore
 *
 * Persists pending OAuth state/PKCE payloads in PHP's native session
 * ($_SESSION). The session must be started by the application before this
 * store is used (e.g. via a session-start middleware run ahead of the
 * OAuth-handling route).
 *
 * @package EzPhp\OAuth
 */
final class SessionOAuthStateStore implements OAuthStateStoreInterface
{
    private const string STORAGE_KEY = '_oauth_state';

    /**
     * @param string               $state
     * @param array<string, mixed> $payload
     * @param int                  $ttlSeconds
     *
     * @return void
     * @throws \RuntimeException When the session has not been started yet.
     */
    public function put(string $state, array $payload, int $ttlSeconds): void
    {
        $this->assertSessionActive();

        $bucket = $this->bucket();
        $bucket[$state] = [
            'payload' => $payload,
            'expiresAt' => time() + $ttlSeconds,
        ];

        $_SESSION[self::STORAGE_KEY] = $bucket;
    }

    /**
     * @param string $state
     *
     * @return array<string, mixed>|null
     * @throws \RuntimeException When the session has not been started yet.
     */
    public function pull(string $state): ?array
    {
        $this->assertSessionActive();

        $bucket = $this->bucket();
        $entry = $bucket[$state] ?? null;
        unset($bucket[$state]);
        $_SESSION[self::STORAGE_KEY] = $bucket;

        if (!is_array($entry) || !isset($entry['payload'], $entry['expiresAt']) || !is_array($entry['payload'])) {
            return null;
        }

        if (!is_int($entry['expiresAt']) || time() >= $entry['expiresAt']) {
            return null;
        }

        /** @var array<string, mixed> $payload */
        $payload = $entry['payload'];

        return $payload;
    }

    /**
     * @return array<string, mixed>
     */
    private function bucket(): array
    {
        $bucket = $_SESSION[self::STORAGE_KEY] ?? [];

        return is_array($bucket) ? $bucket : [];
    }

    /**
     * @return void
     * @throws \RuntimeException
     */
    private function assertSessionActive(): void
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            throw new \RuntimeException(
                'Session is not active. Start the session before using SessionOAuthStateStore ' .
                '(e.g. add a session-start middleware earlier in the pipeline).'
            );
        }
    }
}
