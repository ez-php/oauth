<?php

declare(strict_types=1);

namespace EzPhp\OAuth\Oidc;

use EzPhp\HttpClient\HttpClient;
use EzPhp\HttpClient\HttpClientException;
use EzPhp\OAuth\OAuthException;
use EzPhp\OAuth\OAuthProvider;

/**
 * Class ProviderMetadata
 *
 * The parts of an OpenID Provider's discovery document
 * (`<issuer>/.well-known/openid-configuration`) this module uses.
 *
 * @package EzPhp\OAuth\Oidc
 */
final readonly class ProviderMetadata
{
    /**
     * @param string      $issuer
     * @param string      $authorizationEndpoint
     * @param string      $tokenEndpoint
     * @param string      $jwksUri
     * @param string|null $userinfoEndpoint
     */
    public function __construct(
        public string $issuer,
        public string $authorizationEndpoint,
        public string $tokenEndpoint,
        public string $jwksUri,
        public ?string $userinfoEndpoint = null,
    ) {
    }

    /**
     * Fetch and check the discovery document. The document's `issuer` must equal
     * $issuer exactly (OpenID Connect Discovery §4.3) — otherwise a document served
     * from one issuer could direct token validation to another.
     *
     * @param HttpClient $http
     * @param string     $issuer e.g. `https://accounts.google.com`
     *
     * @return self
     * @throws OAuthException When the document cannot be fetched, is malformed or names another issuer.
     */
    public static function discover(HttpClient $http, string $issuer): self
    {
        $url = rtrim($issuer, '/') . '/.well-known/openid-configuration';

        try {
            $response = $http->get($url)->send();
        } catch (HttpClientException $e) {
            throw new OAuthException("OpenID discovery request to {$url} failed: " . $e->getMessage(), previous: $e);
        }

        $data = $response->ok() ? $response->json() : null;

        if (!is_array($data)) {
            throw new OAuthException("OpenID discovery document at {$url} could not be read (status {$response->status()}).");
        }

        /** @var array<string, mixed> $data */
        $metadata = self::fromArray($data);

        if ($metadata->issuer !== $issuer) {
            throw new OAuthException("OpenID discovery document names issuer \"{$metadata->issuer}\", expected \"{$issuer}\".");
        }

        return $metadata;
    }

    /**
     * Build from a decoded discovery document (e.g. one the application cached).
     *
     * @param array<string, mixed> $data
     *
     * @return self
     * @throws OAuthException When a required field is missing.
     */
    public static function fromArray(array $data): self
    {
        $required = [];

        foreach (['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri'] as $key) {
            if (!is_string($data[$key] ?? null) || $data[$key] === '') {
                throw new OAuthException("OpenID discovery document is missing \"{$key}\".");
            }

            $required[$key] = $data[$key];
        }

        return new self(
            $required['issuer'],
            $required['authorization_endpoint'],
            $required['token_endpoint'],
            $required['jwks_uri'],
            is_string($data['userinfo_endpoint'] ?? null) ? $data['userinfo_endpoint'] : null,
        );
    }

    /**
     * An OAuthProvider for these endpoints. `openid` is added to $scopes when missing.
     *
     * @param string                $clientId
     * @param string                $clientSecret
     * @param string                $redirectUri
     * @param list<string>          $scopes
     * @param array<string, string> $authorizeParams
     *
     * @return OAuthProvider
     */
    public function toProvider(string $clientId, string $clientSecret, string $redirectUri, array $scopes = [], array $authorizeParams = []): OAuthProvider
    {
        if (!in_array('openid', $scopes, true)) {
            array_unshift($scopes, 'openid');
        }

        return new OAuthProvider(
            $this->authorizationEndpoint,
            $this->tokenEndpoint,
            $clientId,
            $clientSecret,
            $redirectUri,
            $scopes,
            $authorizeParams,
        );
    }
}
