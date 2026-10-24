<?php

declare(strict_types=1);

namespace EzPhp\OAuth\Oidc;

use Closure;
use EzPhp\Cache\CacheInterface;
use EzPhp\HttpClient\HttpClient;
use EzPhp\HttpClient\HttpClientException;
use EzPhp\OAuth\OAuthException;

/**
 * Class JwksProvider
 *
 * Fetches a provider's JSON Web Key Set (`jwks_uri`) and keeps it in memory
 * and, optionally, in an ez-php/cache store shared between requests.
 * IdTokenValidator asks for a refresh once when a token names an unknown
 * `kid` — the usual sign of a key rotation.
 *
 * Forced refreshes are throttled: within $refreshCooldownSeconds of the last
 * one (tracked in memory and, with a cache, shared between requests), a
 * refresh request returns the known key set instead of fetching. A token is
 * attacker-controlled input, so without this every request carrying a random
 * `kid` would trigger an outbound JWKS request.
 *
 * @package EzPhp\OAuth\Oidc
 */
final class JwksProvider
{
    /**
     * @var list<array<string, mixed>>|null
     */
    private ?array $keys = null;

    private ?int $lastForcedRefreshAt = null;

    /**
     * @param HttpClient            $http
     * @param string                $jwksUri                From ProviderMetadata::$jwksUri.
     * @param CacheInterface|null   $cache                  Optional shared cache (ez-php/cache, a soft dependency).
     * @param int                   $ttlSeconds             Cache lifetime of a fetched key set.
     * @param int                   $refreshCooldownSeconds Minimum time between two forced refreshes; 0 disables the throttle.
     * @param (Closure(): int)|null $clock                  Current Unix time; null = time().
     */
    public function __construct(
        private readonly HttpClient $http,
        private readonly string $jwksUri,
        private readonly ?CacheInterface $cache = null,
        private readonly int $ttlSeconds = 3600,
        private readonly int $refreshCooldownSeconds = 60,
        private readonly ?Closure $clock = null,
    ) {
    }

    /**
     * The key set's JWKs.
     *
     * @param bool $refresh Bypass the memory and cache copies and fetch again —
     *                      unless the last forced refresh is within the cooldown.
     *
     * @return list<array<string, mixed>>
     * @throws OAuthException When the key set cannot be fetched or decoded.
     */
    public function keys(bool $refresh = false): array
    {
        $refresh = $refresh && !$this->refreshThrottled();

        if (!$refresh && $this->keys !== null) {
            return $this->keys;
        }

        $cacheKey = 'oauth:jwks:' . sha1($this->jwksUri);

        if (!$refresh && $this->cache !== null) {
            $cached = $this->cache->get($cacheKey);

            if (is_array($cached) && array_is_list($cached)) {
                /** @var list<array<string, mixed>> $cached */
                return $this->keys = $cached;
            }
        }

        $this->keys = $this->fetch();
        $this->cache?->set($cacheKey, $this->keys, $this->ttlSeconds);

        if ($refresh) {
            $this->lastForcedRefreshAt = $this->now();
            $this->cache?->set($this->refreshMarkerKey(), true, $this->refreshCooldownSeconds);
        }

        return $this->keys;
    }

    /**
     * Whether a forced refresh happened within the cooldown, in this instance
     * or — through the cache — in another request.
     *
     * @return bool
     */
    private function refreshThrottled(): bool
    {
        if ($this->refreshCooldownSeconds <= 0) {
            return false;
        }

        if ($this->lastForcedRefreshAt !== null && $this->now() - $this->lastForcedRefreshAt < $this->refreshCooldownSeconds) {
            return true;
        }

        return $this->cache?->has($this->refreshMarkerKey()) ?? false;
    }

    private function refreshMarkerKey(): string
    {
        return 'oauth:jwks:refreshed:' . sha1($this->jwksUri);
    }

    private function now(): int
    {
        return $this->clock !== null ? ($this->clock)() : time();
    }

    /**
     * @return list<array<string, mixed>>
     * @throws OAuthException
     */
    private function fetch(): array
    {
        try {
            $response = $this->http->get($this->jwksUri)->send();
        } catch (HttpClientException $e) {
            throw new OAuthException("JWKS request to {$this->jwksUri} failed: " . $e->getMessage(), previous: $e);
        }

        $data = $response->ok() ? $response->json() : null;

        if (!is_array($data) || !is_array($data['keys'] ?? null)) {
            throw new OAuthException("JWKS at {$this->jwksUri} could not be read (status {$response->status()}).");
        }

        $keys = [];

        foreach ($data['keys'] as $key) {
            if (is_array($key) && !array_is_list($key)) {
                /** @var array<string, mixed> $key */
                $keys[] = $key;
            }
        }

        return $keys;
    }
}
