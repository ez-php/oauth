<?php

declare(strict_types=1);

namespace EzPhp\OAuth\Oidc;

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
 * @package EzPhp\OAuth\Oidc
 */
final class JwksProvider
{
    /**
     * @var list<array<string, mixed>>|null
     */
    private ?array $keys = null;

    /**
     * @param HttpClient          $http
     * @param string              $jwksUri    From ProviderMetadata::$jwksUri.
     * @param CacheInterface|null $cache      Optional shared cache (ez-php/cache, a soft dependency).
     * @param int                 $ttlSeconds Cache lifetime of a fetched key set.
     */
    public function __construct(
        private readonly HttpClient $http,
        private readonly string $jwksUri,
        private readonly ?CacheInterface $cache = null,
        private readonly int $ttlSeconds = 3600,
    ) {
    }

    /**
     * The key set's JWKs.
     *
     * @param bool $refresh Bypass the memory and cache copies and fetch again.
     *
     * @return list<array<string, mixed>>
     * @throws OAuthException When the key set cannot be fetched or decoded.
     */
    public function keys(bool $refresh = false): array
    {
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

        return $this->keys;
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
