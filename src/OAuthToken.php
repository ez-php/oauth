<?php

declare(strict_types=1);

namespace EzPhp\OAuth;

/**
 * Class OAuthToken
 *
 * Immutable value object for a token endpoint response.
 *
 * @package EzPhp\OAuth
 */
final readonly class OAuthToken
{
    /**
     * OAuthToken Constructor
     *
     * @param string      $accessToken
     * @param string      $tokenType
     * @param int|null    $expiresIn    Lifetime in seconds from issuance, or null when the provider omitted it.
     * @param string|null $refreshToken
     * @param string|null $scope
     * @param int         $issuedAt     Unix timestamp captured when the token was parsed.
     */
    public function __construct(
        public string $accessToken,
        public string $tokenType,
        public ?int $expiresIn,
        public ?string $refreshToken,
        public ?string $scope,
        public int $issuedAt,
    ) {
    }

    /**
     * Build an OAuthToken from a decoded token endpoint JSON response.
     *
     * @param array<string, mixed> $data
     *
     * @return self
     * @throws OAuthException When the response has no access_token.
     */
    public static function fromArray(array $data): self
    {
        if (!isset($data['access_token']) || !is_string($data['access_token']) || $data['access_token'] === '') {
            throw new OAuthException('Token endpoint response is missing "access_token".');
        }

        $expiresIn = isset($data['expires_in']) && is_numeric($data['expires_in'])
            ? (int) $data['expires_in']
            : null;

        return new self(
            accessToken: $data['access_token'],
            tokenType: is_string($data['token_type'] ?? null) ? $data['token_type'] : 'bearer',
            expiresIn: $expiresIn,
            refreshToken: is_string($data['refresh_token'] ?? null) ? $data['refresh_token'] : null,
            scope: is_string($data['scope'] ?? null) ? $data['scope'] : null,
            issuedAt: time(),
        );
    }

    /**
     * Whether the token's lifetime has elapsed since it was issued.
     *
     * Always false when the provider did not return an expiry.
     *
     * @return bool
     */
    public function isExpired(): bool
    {
        if ($this->expiresIn === null) {
            return false;
        }

        return time() >= ($this->issuedAt + $this->expiresIn);
    }
}
