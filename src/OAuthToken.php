<?php

declare(strict_types=1);

namespace EzPhp\OAuth;

use EzPhp\OAuth\Oidc\IdTokenClaims;

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
     * @param string|null $idToken      Raw OpenID Connect `id_token`, when the response carried one. Unverified
     *                                  unless $idTokenClaims is set; not part of toStorage().
     * @param IdTokenClaims|null $idTokenClaims Verified ID token claims (OAuthClient with an IdTokenValidator).
     */
    public function __construct(
        public string $accessToken,
        public string $tokenType,
        public ?int $expiresIn,
        public ?string $refreshToken,
        public ?string $scope,
        public int $issuedAt,
        public ?string $idToken = null,
        public ?IdTokenClaims $idTokenClaims = null,
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
            idToken: is_string($data['id_token'] ?? null) ? $data['id_token'] : null,
        );
    }

    /**
     * Rebuild a token from toStorage() output (a stored token keeps its original issuedAt).
     *
     * @param array<string, mixed> $data
     *
     * @return self
     * @throws OAuthException When the stored data has no access token.
     */
    public static function fromStorage(array $data): self
    {
        $token = self::fromArray($data);
        $issuedAt = $data['issued_at'] ?? null;

        return is_numeric($issuedAt) ? $token->withIssuedAt((int) $issuedAt) : $token;
    }

    /**
     * Serialisable form for an OAuthTokenStoreInterface: the token endpoint fields plus `issued_at`.
     *
     * @return array{access_token: string, token_type: string, expires_in: int|null, refresh_token: string|null, scope: string|null, issued_at: int}
     */
    public function toStorage(): array
    {
        return [
            'access_token' => $this->accessToken,
            'token_type' => $this->tokenType,
            'expires_in' => $this->expiresIn,
            'refresh_token' => $this->refreshToken,
            'scope' => $this->scope,
            'issued_at' => $this->issuedAt,
        ];
    }

    /**
     * Copy with a different refresh token — used to keep the previous one when a
     * refresh response omits it (providers may rotate it or not).
     *
     * @param string|null $refreshToken
     *
     * @return self
     */
    public function withRefreshToken(?string $refreshToken): self
    {
        return new self($this->accessToken, $this->tokenType, $this->expiresIn, $refreshToken, $this->scope, $this->issuedAt, $this->idToken, $this->idTokenClaims);
    }

    /**
     * Copy with a different issuance timestamp.
     *
     * @param int $issuedAt
     *
     * @return self
     */
    public function withIssuedAt(int $issuedAt): self
    {
        return new self($this->accessToken, $this->tokenType, $this->expiresIn, $this->refreshToken, $this->scope, $issuedAt, $this->idToken, $this->idTokenClaims);
    }

    /**
     * Copy carrying the verified ID token claims.
     *
     * @param IdTokenClaims $claims
     *
     * @return self
     */
    public function withIdTokenClaims(IdTokenClaims $claims): self
    {
        return new self($this->accessToken, $this->tokenType, $this->expiresIn, $this->refreshToken, $this->scope, $this->issuedAt, $this->idToken, $claims);
    }

    /**
     * Whether the token's lifetime has elapsed since it was issued.
     *
     * Always false when the provider did not return an expiry.
     *
     * @param int      $leewaySeconds Treat the token as expired this many seconds early, so a
     *                                request does not race the expiry (clock skew, slow request).
     * @param int|null $now           Current Unix time; null = time(). Injectable for tests.
     *
     * @return bool
     */
    public function isExpired(int $leewaySeconds = 0, ?int $now = null): bool
    {
        if ($this->expiresIn === null) {
            return false;
        }

        return ($now ?? time()) + $leewaySeconds >= ($this->issuedAt + $this->expiresIn);
    }
}
